`timescale 1ns/1ps
module svmvisor_ft601_tb;
    logic clk=0,enable=0,txe_n=1,rx_ready=0,tx_valid=0;
    always #5 clk=~clk;
    tri [31:0] data;
    tri [3:0] be;
    wire oe_n,rd_n,wr_n,rx_valid,tx_ready,fault;
    wire [31:0] rx_data;
    wire [3:0] rx_be;
    logic [31:0] tx_data=32'h12345678,source_base=32'h01230000;
    integer source_words=0,source_index=0,reads=0,writes=0;
    wire rxf_n=source_index>=source_words;
    assign data=!oe_n ? source_base+source_index : 32'bz;
    assign be=!oe_n ? 4'hf : 4'bz;
    logic burst=0;
    svmvisor_ft601 dut(.*);
    always @(posedge clk) begin
        if(!oe_n && !wr_n) $fatal(1,"bus contention");
        if(enable && source_index>0 && source_index<source_words && source_index<1024 && rd_n)
            $fatal(1,"premature RX burst termination at word %0d",source_index);
        if(!rd_n && !rxf_n) source_index<=source_index+1;
        if(rx_valid && rx_ready) begin
            if(rx_data!==source_base+reads || rx_be!==4'hf)
                $fatal(1,"buffered RX word %0d: %h",reads,rx_data);
            reads<=reads+1;
        end
        if(tx_ready && tx_valid) begin
            if(wr_n || txe_n || data!==tx_data || be!==4'hf)
                $fatal(1,"TX handshake/endian error");
            writes<=writes+1;
            if(burst) begin
                tx_data<=tx_data+1;
                if(writes==16) tx_valid<=0;
            end
        end
    end
    task receive_burst(input integer words,input logic [31:0] base);
        @(negedge clk); #1;
        source_words=words; source_index=0; source_base=base; reads=0; rx_ready=1;
        wait(source_index==1); #1; rx_ready=0;
        wait(source_index==words);
        repeat(5) @(posedge clk);
        #1;
        if(reads!=0 || !rx_valid || fault) $fatal(1,"RX reservation/backpressure failure");
        rx_ready=1; wait(reads==words); #1; rx_ready=0;
        repeat(5) @(posedge clk);
        #1; if(rx_valid || fault) $fatal(1,"RX bank did not retire");
    endtask
    initial begin
        #22;
        if(data!==32'bz || be!==4'bz || !rd_n || !wr_n || !oe_n) $fatal(1,"disabled pins");
        enable=1; source_words=16;
        #80;
        if(source_index!=0 || !rd_n) $fatal(1,"RX without capacity");
        receive_burst(16,32'h01230000);
        receive_burst(1024,32'h02340000);
        tx_valid=1;
        #80; if(writes!=0) $fatal(1,"TX while full");
        txe_n=0; wait(writes==1); #1; tx_valid=0; txe_n=1;
        #80; if(writes!=1) $fatal(1,"duplicate transfer");
        burst=1; tx_data=32'h10203040; tx_valid=1; txe_n=0;
        wait(writes==5); #4; txe_n=1;
        repeat(5) @(posedge clk);
        #1; if(writes!=5) $fatal(1,"retired a word while TXE withdrew");
        txe_n=0; wait(writes==17);
        #80; if(writes!=17) $fatal(1,"TX burst lost or duplicated a word");
        // Unexpected endless input cannot exceed the reserved 4 KiB bank.
        source_index=0; source_words=1025; rx_ready=1;
        wait(fault); #1;
        if(source_index!=1024 || rx_valid || !rd_n) $fatal(1,"oversize transaction did not fail stop");
        enable=0; #20; enable=1; #20;
        if(!fault || data!==32'bz || be!==4'bz) $fatal(1,"fault reset or disabled bus drive");
        $display("PASS: FT601 continuous 64B/4KiB RX, backpressure, oversize fault, TXE withdrawal, turnaround and endian");
        $finish;
    end
    initial begin #200000; $fatal(1,"FT601 timeout"); end
endmodule
