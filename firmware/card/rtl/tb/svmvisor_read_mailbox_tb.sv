`timescale 1ns/1ps
module svmvisor_read_mailbox_tb;
    logic [511:0] usb_request=0;
    wire [511:0] usb_response;
    logic usb_request_valid=0,usb_response_ready=0;
    wire usb_request_ready,usb_response_valid;
    logic user_clk=0; always #8 user_clk=~user_clk;
    logic transaction_reset=0,write_valid=0,bad_alignment=0;
    logic [11:0] write_address=0,read_address=0;
    logic [31:0] write_data=0;
    logic [3:0] write_be=15;
    wire [31:0] read_data;
    logic drck=0,capture=0,shift=0,selected=0,tdi=0;
    wire tdo;
    svmvisor_read_mailbox #(.USB_ENABLED(1)) dut(.*);
    function automatic [511:0] frame(input bit response,input integer seq);
        logic [511:0] f; logic [31:0] c;
        f=0; f[31:0]=response ? 32'h50525653 : 32'h51525653;
        f[63:32]=1; f[95:64]=seq; f[127:96]=response ? 0 : 1;
        f[159:128]=8; f[191:160]=32'h100000; f[255:224]=response ? 32'h04030201 : 1;
        c=32'hffffffff;
        for(integer i=0;i<480;i++) c=(c[0]^f[i]) ? (c>>1)^32'hedb88320 : c>>1;
        f[511:480]=~c; return f;
    endfunction
    task scan(input logic [511:0] command,input integer count,output logic [511:0] received);
        selected=1; capture=1; #500; drck=1; #500; drck=0; capture=0; shift=1;
        received=0;
        for(integer i=0;i<count;i++) begin
            tdi=command[i]; received[i]=tdo; #500; drck=1; #500; drck=0;
        end
        shift=0; selected=0; #10000;
    endtask
    task wr(input integer address,input logic [31:0] value);
        @(negedge user_clk); write_valid=1; write_address=address; write_data=value;
        @(negedge user_clk); write_valid=0;
    endtask
    task publish(input logic [511:0] value,input integer words);
        for(integer i=0;i<words;i++) wr('h540+i*4,value[i*32+:32]);
        wr('h580,value[95:64]); #2000;
    endtask
    task check(input integer address,input logic [31:0] expected);
        read_address=address; #1;
        if(read_data!==expected) $fatal(1,"BAR %h expected %h got %h",address,expected,read_data);
    endtask
    logic [511:0] observed,request,response;
    initial begin
        check('h584,32'h31525653); check('h588,0);
        request=frame(0,1); response=frame(1,1);
        scan(request,511,observed); check('h588,0);
        scan(request^512'b1,512,observed); check('h588,0);
        repeat(3) scan(request,512,observed); check('h588,1); check('h508,1);
        // Another request cannot replace the active request, even with a valid CRC.
        repeat(3) scan(frame(0,2),512,observed); check('h588,1); check('h508,1);
        publish(response,15); check('h588,1); check('h58c,0);
        publish(frame(1,2),16); check('h588,1); check('h58c,0);
        publish(response^(512'b1<<300),16); check('h588,1); check('h58c,0);
        // Transaction reset destroys partially staged output but retains its request.
        for(integer i=0;i<8;i++) wr('h540+i*4,response[i*32+:32]);
        @(negedge user_clk); transaction_reset=1;
        repeat(3) @(negedge user_clk); transaction_reset=0;
        for(integer i=8;i<16;i++) wr('h540+i*4,response[i*32+:32]);
        wr('h580,1); #2000; check('h588,1); check('h58c,0);
        publish(response,16); check('h588,0); check('h58c,1);
        repeat(4) scan(0,512,observed);
        if(observed!==response) $fatal(1,"CRC response was not delivered atomically");
        // Replaying the completed request does not execute it again.
        repeat(3) scan(request,512,observed); check('h588,0);
        repeat(3) scan(frame(0,2),512,observed); check('h588,2);
        // Publication during a scan never tears the captured response.
        fork
            scan(0,512,observed);
            begin #100000; publish(frame(1,2),16); end
        join
        if(observed!==response) $fatal(1,"publication tore captured response");
        repeat(4) scan(0,512,observed);
        if(observed!==frame(1,2)) $fatal(1,"second response missing");
        @(negedge user_clk); usb_request=frame(0,3); usb_request_valid=1;
        wait(usb_request_ready); @(negedge user_clk); usb_request_valid=0;
        check('h588,3);
        repeat(3) scan(frame(0,4),512,observed); check('h588,3);
        publish(frame(1,3),16);
        if(!usb_response_valid || usb_response!==frame(1,3) || usb_request_ready)
            $fatal(1,"USB response ownership/backpressure");
        @(negedge user_clk); transaction_reset=1;
        repeat(3) @(negedge user_clk); transaction_reset=0;
        if(!usb_response_valid || usb_response!==frame(1,3)) $fatal(1,"reset lost USB response");
        usb_response_ready=1; @(negedge user_clk); usb_response_ready=0;
        repeat(3) scan(frame(0,4),512,observed); check('h588,4);
        publish(frame(1,4),16);
        if(usb_response_valid) $fatal(1,"JTAG completion delivered to USB owner");
        $display("PASS: read mailbox CRC, occupied slot, reset, atomic publication and USB/JTAG response ownership");
        $finish;
    end
    initial begin #50000000; $fatal(1,"timeout"); end
endmodule
