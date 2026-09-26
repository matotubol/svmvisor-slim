# Standalone FT601 timing check

Run `./firmware/card/test-ft601-timing.ps1` from the repository root with the
configured Vivado installation. This synthesizes and routes an isolated FT601
transport fixture for the Squirrel's `xc7a35tfgg484-2` FPGA. It writes reports and
a routed checkpoint, **not a bitstream**, and does not connect to hardware.

The fixture transmits a deterministic pseudorandom pattern and reduces received
bytes into a rolling checksum. A periodic consumer pause exercises the receive
buffer. There is no PCIe endpoint, process lookup, hypervisor, or memory-reader
backend in this fixture. This isolates transport timing from application work.

Each run snapshots and hashes its RTL, clock wrapper, pin constraints, and Tcl
recipe under `target/firmware/card/ft601-timing/<run>/`. Inspect `timing.rpt`,
`setup-failures.rpt`, `hold-failures.rpt`, `check-timing.rpt`, `drc.rpt`, and
`timing-result.json` in that directory. A failed run retains its evidence.

The I/O constraints assume a 100 MHz FT601 clock and independent clock/data PCB
flight times of 0–1 ns. FTDI's slave setup/hold values of 3/3.5 ns give receive
input delays of 2.5–8 ns after accounting for relative skew. Its master
setup/hold values of 1/4.8 ns give output delays of 3/−4.8 ns after accounting
for round-trip flight. These board-flight bounds are assumptions, not measured
trace delays. Both setup and hold must pass without relaxing those budgets.

Behavioral tests are separate: `./firmware/card/test-ft601-transport.ps1`.
They exercise finite receive bursts, bounded buffering, producer backpressure,
transmit stalls, byte ordering, turnaround, and fail-stop behavior. A behavioral
simulation does not establish routed timing; routed timing does not establish
electrical performance on the board.

The revised PHY and clock wrapper are standalone modules. The existing endpoint
is not switched to them by these scripts; its previous failed timing result is
not superseded by a standalone result.

References: [FTDI FT600/FT601 datasheet](https://ftdichip.com/wp-content/uploads/2024/11/DS_FT600Q-FT601Q-IC-Datasheet.pdf),
[AMD 7-series clocking resources](https://www.amd.com/content/dam/xilinx/support/documents/user_guides/ug472_7Series_Clocking.pdf).
