`timescale 1ns/1ps
// Compensated 100 MHz FT601 sampling clock and a 4 ns delayed pin-launch clock.
// Both clocks are real MMCM outputs; implementation must time their relationship.
module ft601_transport_clock (
    input wire clk_in,
    output wire clk, io_clk, locked
);
    wire input_clock, feedback, feedback_buffered, sample_clock, launch_clock;
    IBUF input_buffer(.I(clk_in), .O(input_clock));
    BUFG feedback_buffer(.I(feedback), .O(feedback_buffered));
    BUFG sample_buffer(.I(sample_clock), .O(clk));
    BUFG launch_buffer(.I(launch_clock), .O(io_clk));
    MMCME2_BASE #(
        .BANDWIDTH("OPTIMIZED"), .CLKIN1_PERIOD(10.0),
        .DIVCLK_DIVIDE(1), .CLKFBOUT_MULT_F(10.0),
        .CLKOUT0_DIVIDE_F(10.0), .CLKOUT0_PHASE(0.0),
        .CLKOUT1_DIVIDE(10), .CLKOUT1_PHASE(144.0),
        .STARTUP_WAIT("FALSE")
    ) clock_manager (
        .CLKIN1(input_clock), .CLKFBIN(feedback_buffered), .CLKFBOUT(feedback),
        .CLKOUT0(sample_clock), .CLKOUT1(launch_clock), .LOCKED(locked),
        .PWRDWN(1'b0), .RST(1'b0)
    );
endmodule
