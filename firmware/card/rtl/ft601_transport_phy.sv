`timescale 1ns/1ps
// Standalone FT245 PHY. clk samples FT601 transfers; the compensated io_clk
// launches pins 4 ns later. Reserve one complete 4 KiB bank before reading.
module ft601_transport_phy (
    input logic clk, io_clk, enable,
    inout wire [31:0] data,
    inout wire [3:0] be,
    input logic rxf_n, txe_n,
    (* IOB="TRUE" *) output logic oe_n=1, rd_n=1, wr_n=1,
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
    state_t state=IDLE, next_state;
    (* IOB="TRUE" *) logic [31:0] transmit_word=0;
    // Separate preserved T registers allow every pin's tristate FF to occupy
    // its own IOB instead of one high-fanout fabric enable and a pin-side LUT.
    (* IOB="TRUE", DONT_TOUCH="TRUE" *) logic [31:0] data_tristate=32'hffffffff;
    (* IOB="TRUE", DONT_TOUCH="TRUE" *) logic [3:0] be_tristate=4'hf;
    (* IOB="TRUE" *) logic [31:0] sampled_data=0;
    (* IOB="TRUE" *) logic [3:0] sampled_be=0;
    (* IOB="TRUE" *) logic receive_empty=1, transmit_full=1;
    logic sampled_read=0;
    (* ram_style="distributed" *) logic [35:0] receive_bank[0:1023];
    logic [9:0] read_index=0, write_index=0;
    logic [10:0] receive_count=0, burst_words=0;
    logic limit_pending=0;
    genvar bit_index;
    generate
        for(bit_index=0; bit_index<32; bit_index=bit_index+1) begin: data_pin
            assign data[bit_index]=data_tristate[bit_index] ? 1'bz : transmit_word[bit_index];
        end
        for(bit_index=0; bit_index<4; bit_index=bit_index+1) begin: be_pin
            assign be[bit_index]=be_tristate[bit_index] ? 1'bz : 1'b1;
        end
    endgenerate
    assign rx_data=receive_bank[read_index][31:0];
    assign rx_be=receive_bank[read_index][35:32];
    // A completed bank is independent of physical transmit ownership. Keep
    // TURN excluded until the full-bank boundary/fault decision has completed.
    assign rx_valid=enable && !fault && receive_count!=0 &&
        (state==IDLE || state==TX_WORD) && !sampled_read;
    // The backend retires exactly the word accepted on this sampling edge.
    // A previously sampled TXE# cannot be used as proof of acceptance.
    assign tx_ready=enable && !fault && !wr_n && !txe_n;
    always @(posedge clk) begin
        sampled_data<=data; sampled_be<=be;
        receive_empty<=rxf_n; transmit_full<=txe_n;
        sampled_read<=enable && !fault && !rd_n;
        // Input registers isolate the short external setup budget from the
        // bank's address, write-enable and storage paths. Account one cycle later.
        if(sampled_read && !receive_empty && !fault) begin
            if(receive_count==1024 || burst_words==1024) fault<=1;
            else begin
                receive_bank[write_index]<={sampled_be,sampled_data};
                write_index<=write_index+1'b1;
                receive_count<=receive_count+1'b1;
                burst_words<=burst_words+1'b1;
                if(burst_words==1023) limit_pending<=1;
            end
        end else if(rx_valid && rx_ready) begin
            read_index<=read_index+1'b1;
            receive_count<=receive_count-1'b1;
        end
        if(limit_pending && !receive_empty) fault<=1;
        if(state==IDLE && !sampled_read) begin
            burst_words<=0; limit_pending<=0;
        end
    end
    always @* begin
        next_state=state;
        if(!enable || fault) next_state=IDLE;
        else case(state)
            IDLE: begin
                if(tx_valid && !transmit_full) next_state=TX_WORD;
                else if(rx_ready && receive_count==0 && !sampled_read && !receive_empty)
                    next_state=RX_SETUP;
            end
            RX_SETUP: next_state=!receive_empty ? RX_WORD : TURN;
            RX_WORD: begin
                // burst_words excludes this edge's IOB capture. Stop after its
                // 1024th accepted word, allowing the pipeline to commit in TURN.
                if(receive_empty || (burst_words==1023 && sampled_read)) next_state=TURN;
            end
            TX_WORD: if(!tx_valid || transmit_full) next_state=TURN;
            // Do not expose a full bank in the one-cycle interval before an
            // oversized transaction's sticky fault is registered.
            default: next_state=(limit_pending && !receive_empty) ? TURN : IDLE;
        endcase
    end
    always @(posedge io_clk) begin
        state<=next_state;
        // No combinational logic follows these pin registers.
        oe_n<=!(next_state==RX_SETUP || next_state==RX_WORD);
        rd_n<=!(next_state==RX_WORD);
        wr_n<=!(next_state==TX_WORD);
        data_tristate<={32{next_state!=TX_WORD}};
        be_tristate<={4{next_state!=TX_WORD}};
        transmit_word<=tx_data;
    end
endmodule
