# Standalone, synthetic-data implementation check; deliberately emits no bitstream.
proc require_timing_coverage {report} {
    # check_timing has no object-query equivalent. Read only its named counts,
    # fail on missing/changed report structure, and keep the complete evidence.
    foreach check {no_clock constant_clock unconstrained_internal_endpoints no_input_delay
        multiple_clock generated_clocks loops partial_input_delay partial_output_delay latch_loops} {
        set matches [regexp -all -inline [format {checking %s \(([0-9]+)\)} $check] $report]
        if {[llength $matches] == 0} {error "Missing check_timing result: $check"}
        foreach {label count} $matches {
            if {$count != 0} {error "Timing coverage failed: $check ($count)"}
        }
    }
    # The only output without an external timing receiver is the status LED.
    set matches [regexp -all -inline {checking no_output_delay \(([0-9]+)\)} $report]
    if {[llength $matches] == 0} {error "Missing no_output_delay result"}
    foreach {label count} $matches {
        if {$count != 1} {error "Unexpected outputs without delay: $count"}
    }
    if {![regexp {There are 0 ports with no output delay specified\.} $report] ||
        ![regexp {There (is 1 port|are 1 ports) with no output delay but user has a false path constraint} $report] ||
        ![regexp -line {^status\r?$} $report]} {
        error "Only the explicitly excepted status LED may lack output delay"
    }
}

proc require_finite_slack {value name} {
    if {![string is double -strict $value] || ![expr {abs($value) < 1e9}]} {
        error "Missing or non-finite $name slack: $value"
    }
    if {$value < 0} {error "FT601 $name timing failed: $value ns"}
}

if {$argc != 2} {error "usage: ft601-transport.tcl source_root output_dir"}
set source_root [file normalize [lindex $argv 0]]
set output_dir [file normalize [lindex $argv 1]]
cd $output_dir
create_project -in_memory -part xc7a35tfgg484-2
set version_file [open tool-version.txt w]
puts $version_file [version]
close $version_file
foreach source {rtl/ft601_transport_phy.sv rtl/ft601_transport_clock.sv rtl/tb/ft601_transport_bench.sv} {
    read_verilog -sv [file join $source_root $source]
}
read_xdc [file join $source_root rtl/tb/ft601_transport_bench.xdc]
synth_design -top ft601_transport_bench -part xc7a35tfgg484-2 -flatten_hierarchy none
# Check selectors and actual derived clocks, without cutting the related clock
# paths between the sampling and launch domains.
if {[llength [get_pins -quiet {startup_reg[0]/D}]] != 1} {
    error "Missing first lock synchronizer timing endpoint"
}
set mmcm [get_cells -hier -filter {REF_NAME == MMCME2_BASE || REF_NAME == MMCME2_ADV}]
if {[llength $mmcm] != 1 || [llength [get_clocks -quiet ft601_clock]] != 1} {
    error "Expected one MMCM and one FT601 source clock"
}
foreach output {CLKOUT0 CLKOUT1} expected_waveform {{0.0 5.0} {4.0 9.0}} {
    set pins [get_pins -quiet $mmcm/$output]
    if {[llength $pins] != 1} {error "Missing MMCM output: $output"}
    set derived [get_clocks -quiet -of_objects $pins]
    if {[llength $derived] != 1 || ![get_property IS_GENERATED $derived] ||
        [get_property MASTER_CLOCK $derived] ne "ft601_clock" ||
        abs([get_property PERIOD $derived] - 10.0) > 0.001} {
        error "Missing or unexpected generated clock on $output"
    }
    set waveform [get_property WAVEFORM $derived]
    if {[llength $waveform] != 2} {error "Missing generated-clock waveform: $output"}
    foreach actual $waveform expected $expected_waveform {
        if {abs($actual - $expected) > 0.001} {error "Unexpected clock phase on $output: $waveform"}
    }
}
opt_design
place_design
phys_opt_design
route_design
report_timing_summary -delay_type min_max -report_unconstrained -warn_on_violation -file timing.rpt
report_timing -delay_type max -max_paths 50 -slack_lesser_than 0 -file setup-failures.rpt
report_timing -delay_type min -max_paths 50 -slack_lesser_than 0 -file hold-failures.rpt
report_utilization -file utilization.rpt
report_drc -file drc.rpt
report_clocks -file clocks.rpt
report_pulse_width -all_violators -warn_on_violation -file pulse-width.rpt
set coverage [check_timing -verbose -return_string]
set coverage_file [open check-timing.rpt w]
puts $coverage_file $coverage
close $coverage_file
write_checkpoint -force transport-routed.dcp
set setup [get_timing_paths -delay_type max -max_paths 1]
set hold [get_timing_paths -delay_type min -max_paths 1]
if {[llength $setup] != 1 || [llength $hold] != 1} {error "Missing timing paths"}
set setup_slack [get_property SLACK $setup]
set hold_slack [get_property SLACK $hold]
require_timing_coverage $coverage
require_finite_slack $setup_slack setup
require_finite_slack $hold_slack hold
set violations [get_drc_violations -quiet -filter {SEVERITY == Error || SEVERITY == {Critical Warning}}]
if {[llength $violations] != 0} {error "FT601 standalone DRC failed: $violations"}
# These reports issue Critical Warnings for violations, including pulse widths
# not represented by get_timing_paths. Query the message system, not DRC objects.
# This flow runs in this process (no launch_runs subprocesses).
foreach severity {ERROR {CRITICAL WARNING}} {
    set count [get_msg_config -severity $severity -count]
    if {![string is integer -strict $count] || $count != 0} {
        error "FT601 standalone run has $severity messages: $count"
    }
}
set record [open timing-result.json w]
puts $record "{\"passed\": true, \"setup_slack_ns\": $setup_slack, \"hold_slack_ns\": $hold_slack, \"coverage_checked\": true, \"pulse_width_checked\": true, \"hardware_tested\": false, \"standalone_synthetic_only\": true}"
close $record
puts "PASS: FT601 standalone timing, coverage, pulse width and DRC; no hardware image generated"
