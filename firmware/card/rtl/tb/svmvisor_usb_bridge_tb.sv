`timescale 1ns/1ps
module svmvisor_usb_bridge_tb;
    logic usb_clk=0,user_clk=0,board_clk=0;
    always #5 usb_clk=~usb_clk;
    always #4 user_clk=~user_clk;
    always #7 board_clk=~board_clk;
    logic enable=1,rx_valid=0,tx_ready=0;
    logic [31:0] rx_data=0;
    logic [3:0] rx_be=4'hf;
    wire rx_ready,tx_valid,fault,physical_valid,physical_response_ready;
    wire [31:0] tx_data;
    wire [511:0] physical_request;
    logic physical_ready=0,physical_response_valid=0;
    logic [511:0] physical_response=0,snapshot_frame=0;
    logic [31:0] vectors[0:95];
    integer sent=0,received=0,cycles=0;
    svmvisor_usb_bridge #(.PARTIAL_TIMEOUT_CYCLES(64)) dut(.*);
    always @(negedge usb_clk) begin
        cycles<=cycles+1;
        tx_ready<=cycles%5!=0;
    end
    always @(posedge usb_clk) if(tx_valid && tx_ready) begin
        if(received<16) begin
            if(tx_data!==vectors[16+received]) $fatal(1,"physical response word %0d",received);
        end else if(tx_data!==vectors[64+received-16]) $fatal(1,"identity response word %0d",received);
        received<=received+1;
    end
    task send_frame(input integer start_word,input bit corrupt);
        for(integer i=0;i<16;i++) begin
            @(negedge usb_clk);
            while(!rx_ready) @(negedge usb_clk);
            rx_data=vectors[start_word+i] ^ ((corrupt && i==15) ? 1 : 0); rx_valid=1;
            @(negedge usb_clk); rx_valid=0;
        end
    endtask
    initial begin
        $readmemh("ft601_wire_vectors.mem",vectors);
        for(integer i=0;i<16;i++) begin
            snapshot_frame[i*32+:32]=vectors[48+i];
            physical_response[i*32+:32]=vectors[16+i];
        end
        #100;
        fork
            send_frame(0,0);
            begin
                wait(physical_valid);
                for(integer i=0;i<16;i++) if(physical_request[i*32+:32]!==vectors[i])
                    $fatal(1,"physical request word %0d",i);
                // Hold the backend busy; the complete request must remain stable.
                repeat(12) @(negedge user_clk);
                physical_ready=1;
                @(negedge user_clk); physical_ready=0;
                wait(!physical_valid);
                repeat(12) @(negedge user_clk);
                physical_response_valid=1;
                wait(physical_response_ready);
                @(negedge user_clk); physical_response_valid=0;
            end
        join
        wait(received==16); wait(rx_ready);
        send_frame(32,0);
        wait(received==48); wait(rx_ready);
        if(fault) $fatal(1,"valid traffic faulted");
        // Corrupt complete frame is sticky, with no magic-search recovery.
        send_frame(32,1);
        repeat(20) @(negedge usb_clk);
        if(!fault || rx_ready || tx_valid) $fatal(1,"bad CRC did not fail stop");
        enable=0; repeat(10) @(negedge usb_clk); enable=1;
        repeat(10) @(negedge usb_clk);
        if(!fault || rx_ready) $fatal(1,"enable cycle cleared uncertain stream");
        $display("PASS: USB golden physical/identity frames, CDC stalls, backpressure, CRC fail-stop");
        $finish;
    end
    initial begin #200000; $fatal(1,"USB bridge timeout"); end
endmodule
