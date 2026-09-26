`timescale 1ns/1ps
// Standalone implementation fixture. Only synthetic transmit data and a receive
// checksum are present; there is no PCIe endpoint, mailbox, or memory reader.
module ft601_transport_bench (
    input wire ft601_clk, ft601_rxf_n, ft601_txe_n,
    inout wire [31:0] ft601_data,
    inout wire [3:0] ft601_be,
    output wire ft601_oe_n, ft601_rd_n, ft601_wr_n,
    output wire status
);
    wire clk, io_clk, locked;
    ft601_transport_clock clocking_unit(.clk_in(ft601_clk), .clk, .io_clk, .locked);
    (* ASYNC_REG="TRUE" *) logic [2:0] startup=0;
    always @(posedge clk) startup <= {startup[1:0], locked};

    logic [31:0] pattern=32'h12345678, checksum=0;
    logic [7:0] phase=0;
    wire [31:0] rx_data;
    wire [3:0] rx_be;
    wire rx_valid, tx_ready, fault;
    wire enable=startup[2];
    wire tx_valid=enable && !phase[7];
    wire rx_ready=enable && phase[6];
    always @(posedge clk) begin
        if(enable) phase <= phase+1'b1;
        if(tx_valid && tx_ready)
            pattern <= {pattern[30:0], pattern[31]^pattern[21]^pattern[1]^pattern[0]};
        if(rx_valid && rx_ready)
            checksum <= {checksum[30:0], checksum[31]} ^ rx_data ^ {28'b0, rx_be};
    end
    assign status=fault ^ (^checksum);
    ft601_transport_phy fifo(
        .clk, .io_clk, .enable, .data(ft601_data), .be(ft601_be),
        .rxf_n(ft601_rxf_n), .txe_n(ft601_txe_n),
        .oe_n(ft601_oe_n), .rd_n(ft601_rd_n), .wr_n(ft601_wr_n),
        .rx_data, .rx_be, .rx_valid, .rx_ready,
        .tx_data(pattern), .tx_valid, .tx_ready, .fault
    );
endmodule
