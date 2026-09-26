`timescale 1ns/1ps
// Single-channel FT245 synchronous FIFO. Reserve a complete 4 KiB receive bank
// before asserting RD#, then drain the transaction without protocol backpressure.
// No padding, endian conversion, unbounded receive, or PCIe interface exists.
module svmvisor_ft601 (
    input logic clk, enable,
    inout wire [31:0] data,
    inout wire [3:0] be,
    input logic rxf_n, txe_n,
    output logic oe_n, rd_n, wr_n,
    output wire [31:0] rx_data,
    output wire [3:0] rx_be,
    output wire rx_valid,
    input logic rx_ready,
    input logic [31:0] tx_data,
    input logic tx_valid,
    output wire tx_ready,
    output logic fault=0
);
    typedef enum logic [2:0] {IDLE, RX_SETUP, RX_WORD, TX_WORD, TURN} state_t;
    state_t state=IDLE;
    logic [31:0] transmit_word=0;
    logic receive_empty=1,transmit_full=1;
    (* ram_style="distributed" *) logic [35:0] receive_bank[0:1023];
    logic [9:0] read_index=0,write_index=0;
    logic [10:0] receive_count=0,burst_words=0;
    logic limit_pending=0;
    always @(posedge clk) begin receive_empty<=rxf_n; transmit_full<=txe_n; end
    wire transmitting=enable && state==TX_WORD;
    assign data=transmitting ? transmit_word : 32'bz;
    assign be=transmitting ? 4'hf : 4'bz;
    assign rx_data=receive_bank[read_index][31:0];
    assign rx_be=receive_bank[read_index][35:32];
    // Transfer qualification uses the flags at the rising sampling edge. A flag
    // may change after the preceding edge; never retire a word the chip refused.
    assign rx_valid=enable && !fault && receive_count!=0 && state==IDLE;
    assign tx_ready=transmitting && !txe_n;
    always @(posedge clk) begin
        if(enable && !fault) begin
            if(state==IDLE) begin burst_words<=0; limit_pending<=0; end
            if(state==RX_WORD && !rxf_n) begin
                if(receive_count==1024 || burst_words==1024) fault<=1;
                else begin
                    receive_bank[write_index]<={be,data};
                    write_index<=write_index+1; receive_count<=receive_count+1;
                    burst_words<=burst_words+1;
                    if(burst_words==1023) limit_pending<=1;
                end
            end else if(rx_valid && rx_ready) begin
                read_index<=read_index+1; receive_count<=receive_count-1;
            end
            // A complete FT245 bank is the documented maximum transaction. After
            // turnaround the slave must report its end; endless data fails closed.
            if(state==TURN && limit_pending && !rxf_n) fault<=1;
        end
    end
    always @* begin
        oe_n=1; rd_n=1; wr_n=1;
        if(enable && !fault) begin
            oe_n=!(state==RX_SETUP || state==RX_WORD);
            rd_n=!(state==RX_WORD);
            wr_n=!(state==TX_WORD);
        end
    end
    // The slave samples rising edges. Falling-edge launch gives its output hold
    // requirement half a cycle and keeps data/strobes fixed across each transfer.
    always @(negedge clk) begin
        if(!enable || fault) state<=IDLE;
        else case(state)
            IDLE: begin
                if(tx_valid && !transmit_full) begin state<=TX_WORD; transmit_word<=tx_data; end
                else if(rx_ready && receive_count==0 && !receive_empty) state<=RX_SETUP;
            end
            RX_SETUP: state<=!receive_empty ? RX_WORD : TURN;
            RX_WORD: if(receive_empty || burst_words==1024) state<=TURN;
            TX_WORD: begin
                if(tx_valid && !transmit_full) transmit_word<=tx_data;
                else state<=TURN;
            end
            default: state<=IDLE;
        endcase
    end
endmodule
