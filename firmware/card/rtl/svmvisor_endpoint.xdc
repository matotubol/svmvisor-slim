# Pinned Squirrel board mapping; no upstream controller or timing exceptions.
set_property PACKAGE_PIN H4 [get_ports clk]
set_property PACKAGE_PIN AB3 [get_ports user_sw1_n]
set_property PACKAGE_PIN B13 [get_ports pcie_perst_n]
set_property PACKAGE_PIN Y6 [get_ports user_ld1]
set_property PACKAGE_PIN AB5 [get_ports user_ld2]
set_property PACKAGE_PIN F21 [get_ports ft2232_rst_n]
set_property PACKAGE_PIN Y9 [get_ports ft601_rst_n]
set_property PACKAGE_PIN AB7 [get_ports ft601_wr_n]
set_property PACKAGE_PIN AA6 [get_ports ft601_rd_n]
set_property PACKAGE_PIN AB6 [get_ports ft601_oe_n]
set_property PACKAGE_PIN Y8 [get_ports ft601_siwu_n]
set_property PACKAGE_PIN A14 [get_ports pcie_wake_n]
set_property IOSTANDARD LVCMOS33 [get_ports {clk user_sw1_n pcie_perst_n user_ld1 user_ld2 ft2232_rst_n ft601_rst_n ft601_siwu_n pcie_wake_n}]
set_property PACKAGE_PIN A10 [get_ports {pcie_rx_n[0]}]
set_property PACKAGE_PIN B10 [get_ports {pcie_rx_p[0]}]
set_property PACKAGE_PIN A6 [get_ports {pcie_tx_n[0]}]
set_property PACKAGE_PIN B6 [get_ports {pcie_tx_p[0]}]
set_property PACKAGE_PIN E6 [get_ports pcie_clk_n]
set_property PACKAGE_PIN F6 [get_ports pcie_clk_p]
create_clock -period 10.000 -name board_clk [get_ports clk]
create_clock -period 10.000 -name pcie_refclk [get_ports pcie_clk_p]
# Reader is limited to 1 MHz. XPM supplies mailbox CDC constraints; no broad
# clock-group exception cuts the journal or board-clock publication logic.
create_clock -period 1000.000 -name jtag_drck [get_pins user2/DRCK]
create_clock -period 1000.000 -name cpu_jtag_drck [get_pins user3/DRCK]
create_clock -period 1000.000 -name read_jtag_drck [get_pins user4/DRCK]
set_false_path -through [get_pins {user4/CAPTURE user4/SHIFT user4/SEL}]
set_max_delay -datapath_only 100 -from [get_pins user4/TDI] -to [get_pins -hier -filter {NAME =~ read_mailbox/incoming_reg*/D || NAME =~ read_mailbox/request_mailbox_reg*/D || NAME =~ read_mailbox/request_crc_reg*/D || NAME =~ read_mailbox/request_send_reg/D}]
set_min_delay 0 -from [get_pins user4/TDI] -to [get_pins -hier -filter {NAME =~ read_mailbox/incoming_reg*/D || NAME =~ read_mailbox/request_mailbox_reg*/D || NAME =~ read_mailbox/request_crc_reg*/D || NAME =~ read_mailbox/request_send_reg/D}]
# UG903: register clock pins are valid startpoints; Q would segment the
# register's other timing paths. Include C->Q in the half-cycle budget.
set_max_delay -datapath_only 100 -from [get_pins -hier -filter {NAME =~ read_mailbox/scan_bits_reg*/C}] -to [get_pins user4/TDO]
set_min_delay 0 -from [get_pins -hier -filter {NAME =~ read_mailbox/scan_bits_reg*/C}] -to [get_pins user4/TDO]
set_false_path -through [get_pins {user3/CAPTURE user3/SHIFT user3/SEL}]
# Hard TAP TDI is stable for the 1MHz scan half-cycle. Constrain only its
# fabric route to the first selector register to100ns (400ns margin).
set_max_delay -datapath_only 100 -from [get_pins user3/TDI] -to [get_pins -hier -filter {NAME =~ cpu_snapshot/selector_bits_reg*/D}]
set_min_delay 0 -from [get_pins user3/TDI] -to [get_pins -hier -filter {NAME =~ cpu_snapshot/selector_bits_reg*/D}]
# UG470p164: BSCAN registers TDO on fallingTCK; DRCK-driven shift data
# gets a half-cycle. Budget100ns of the500ns half-cycle for its fabric route.
set_max_delay -datapath_only 100 -from [get_pins -hier -filter {NAME =~ cpu_snapshot/scan_capture_buffer_reg*/C}] -to [get_pins user3/TDO]
set_min_delay 0 -from [get_pins -hier -filter {NAME =~ cpu_snapshot/scan_capture_buffer_reg*/C}] -to [get_pins user3/TDO]
# Hard TAP control outputs are not fabric timing startpoints. These three
# controls are generated with DRCK by BSCAN, and only qualify the scan register.
set_false_path -through [get_pins {user2/CAPTURE user2/SHIFT user2/SEL}]
# Link status is asynchronous to the board clock; only the first ASYNC_REG
# stage is excluded. The second stage and all consumers remain timed.
set_false_path -to [get_pins {snapshot/link_sync_reg[0]/D}]
set_property CFGBVS Vcco [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]
set_property BITSTREAM.CONFIG.SPI_FALL_EDGE YES [current_design]
set_property BITSTREAM.CONFIG.CONFIGRATE 66 [current_design]
set_property BITSTREAM.GENERAL.COMPRESS TRUE [current_design]
set_property BITSTREAM.CONFIG.UNUSEDPIN Pullnone [current_design]
# Asynchronous physical switch only enters the first synchronizer stage.
set_false_path -from [get_ports user_sw1_n] -to [get_pins -hier -filter {NAME =~ *switch_sync_reg[0]/D}]
# PERST# is the platform's asynchronous reset, not a timed data input.
set_false_path -from [get_ports pcie_perst_n]
# A single registered, monotonic startup reset release drives only the vendor
# sys_rst_n network. PG054 defines this as an asynchronous reset; its core
# reset synchronizers release each internal domain. Unlike a clock-group cut,
# this exception cannot hide application data crossings between the clocks.
set_false_path -from [get_pins bypass_latch/core_release_reg/C]
# Status LEDs and static output controls have no external synchronous receiver.
set_false_path -to [get_ports {user_ld1 user_ld2 ft2232_rst_n ft601_rst_n ft601_siwu_n pcie_wake_n}]
# Dedicated configuration functions verified against AMD Vivado's
# xc7a35tfgg484-2 package database (PIN_FUNC), not borrowed board GPIOs:
# T19 FCS_B, P22 D00_MOSI, R22 D01_DIN, P21 D02, R21 D03.
# CCLK is the dedicated L12 pin reached only through STARTUPE2.
set_property PACKAGE_PIN T19 [get_ports flash_cs_n]
set_property PACKAGE_PIN P22 [get_ports flash_mosi]
set_property PACKAGE_PIN R22 [get_ports flash_miso]
set_property PACKAGE_PIN P21 [get_ports flash_wp_n]
set_property PACKAGE_PIN R21 [get_ports flash_hold_n]
set_property IOSTANDARD LVCMOS33 [get_ports {flash_cs_n flash_mosi flash_miso flash_wp_n flash_hold_n}]
set_property SLEW FAST [get_ports {flash_cs_n flash_mosi}]
set_property DRIVE 8 [get_ports {flash_cs_n flash_mosi flash_wp_n flash_hold_n}]
# SPI is source-synchronous mode 0, 15.625 MHz. Read data changes on the
# preceding falling SCK edge; no broad false path masks the MISO sampling path.
# IS25LP256D Rev.A section9.6 tV<=8ns, DS181 STARTUP<=6.7ns;
# endpoint.tcl includes actual clock routing plus a 0..2ns board roundtrip budget.
# Conditional generated-clock and SPI I/O delays are applied after synthesis
# by endpoint.tcl (Vivado XDC does not support conditional Tcl commands).
set_false_path -to [get_ports {flash_cs_n flash_wp_n flash_hold_n}]

# Squirrel FT601 bus pin mapping from pinned board support c538c417. Only pin
# locations are reused; no upstream FIFO, PCIe requester, or timing exceptions.
set_property PACKAGE_PIN Y18  [get_ports {ft601_be[0]}]
set_property PACKAGE_PIN AA18 [get_ports {ft601_be[1]}]
set_property PACKAGE_PIN AB18 [get_ports {ft601_be[2]}]
set_property PACKAGE_PIN W17  [get_ports {ft601_be[3]}]
set_property PACKAGE_PIN N13  [get_ports {ft601_data[0]}]
set_property PACKAGE_PIN N14  [get_ports {ft601_data[1]}]
set_property PACKAGE_PIN N15  [get_ports {ft601_data[2]}]
set_property PACKAGE_PIN P15  [get_ports {ft601_data[3]}]
set_property PACKAGE_PIN P16  [get_ports {ft601_data[4]}]
set_property PACKAGE_PIN N17  [get_ports {ft601_data[5]}]
set_property PACKAGE_PIN P17  [get_ports {ft601_data[6]}]
set_property PACKAGE_PIN R17  [get_ports {ft601_data[7]}]
set_property PACKAGE_PIN P19  [get_ports {ft601_data[8]}]
set_property PACKAGE_PIN R18  [get_ports {ft601_data[9]}]
set_property PACKAGE_PIN R19  [get_ports {ft601_data[10]}]
set_property PACKAGE_PIN T18  [get_ports {ft601_data[11]}]
set_property PACKAGE_PIN U18  [get_ports {ft601_data[12]}]
set_property PACKAGE_PIN V18  [get_ports {ft601_data[13]}]
set_property PACKAGE_PIN V19  [get_ports {ft601_data[14]}]
set_property PACKAGE_PIN V17  [get_ports {ft601_data[15]}]
set_property PACKAGE_PIN W20  [get_ports {ft601_data[16]}]
set_property PACKAGE_PIN Y19  [get_ports {ft601_data[17]}]
set_property PACKAGE_PIN T21  [get_ports {ft601_data[18]}]
set_property PACKAGE_PIN T20  [get_ports {ft601_data[19]}]
set_property PACKAGE_PIN U21  [get_ports {ft601_data[20]}]
set_property PACKAGE_PIN V20  [get_ports {ft601_data[21]}]
set_property PACKAGE_PIN W22  [get_ports {ft601_data[22]}]
set_property PACKAGE_PIN W21  [get_ports {ft601_data[23]}]
set_property PACKAGE_PIN Y22  [get_ports {ft601_data[24]}]
set_property PACKAGE_PIN Y21  [get_ports {ft601_data[25]}]
set_property PACKAGE_PIN AA21 [get_ports {ft601_data[26]}]
set_property PACKAGE_PIN AB22 [get_ports {ft601_data[27]}]
set_property PACKAGE_PIN AA20 [get_ports {ft601_data[28]}]
set_property PACKAGE_PIN AB21 [get_ports {ft601_data[29]}]
set_property PACKAGE_PIN AA19 [get_ports {ft601_data[30]}]
set_property PACKAGE_PIN AB20 [get_ports {ft601_data[31]}]
set_property PACKAGE_PIN AB8 [get_ports ft601_rxf_n]
set_property PACKAGE_PIN AA8 [get_ports ft601_txe_n]
set_property PACKAGE_PIN W19 [get_ports ft601_clk]
set_property IOSTANDARD LVCMOS33 [get_ports {ft601_clk ft601_rxf_n ft601_txe_n ft601_be[*] ft601_data[*] ft601_wr_n ft601_rd_n ft601_oe_n}]
set_property SLEW FAST [get_ports {ft601_be[*] ft601_data[*] ft601_wr_n ft601_rd_n ft601_oe_n}]
create_clock -period 10.000 -name ft601_clock [get_ports ft601_clk]
# DS_FT600Q-FT601Q v1.06 table 4.2: slave setup T1=3 ns, hold T2=3.5 ns;
# master setup T3=1 ns, hold T4=4.8 ns. Assume EACH PCB clock/data flight 0..1 ns.
# RX relative skew is -1..+1: min=T2-1=2.5, max=10-T1+1=8 ns.
# TX roundtrip flight is 0..2: max=T3+2=3, min=0-T4=-4.8 ns.
# These are explicit candidate assumptions, NOT measured Squirrel trace delays.
# Falling-edge launch and both setup/hold must close; verify PCB bounds before use.
set_input_delay -clock ft601_clock -min 2.5 [get_ports {ft601_data[*] ft601_be[*] ft601_rxf_n ft601_txe_n}]
set_input_delay -clock ft601_clock -max 8.0 [get_ports {ft601_data[*] ft601_be[*] ft601_rxf_n ft601_txe_n}]
set_output_delay -clock ft601_clock -max 3.0 [get_ports {ft601_data[*] ft601_be[*] ft601_wr_n ft601_rd_n ft601_oe_n}]
set_output_delay -clock ft601_clock -min -4.8 [get_ports {ft601_data[*] ft601_be[*] ft601_wr_n ft601_rd_n ft601_oe_n}]
# XPM supplies bounded-data CDC constraints. No asynchronous clock-group cut.
