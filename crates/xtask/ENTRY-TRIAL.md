# Retired guest entry trial

The ARM/QUERY VMMCALL experiment, its native client and the
native-entry-trial build feature have been removed from the supported artifact.
cargo xtask entry-trial and the old --entry-trial build flag return explicit
errors before native work, building or flashing.

The producer uses resident-runtime with live reading disabled. Useful inert VMCB
trial primitives remain behind svm-entry-trial for offline architecture tests;
they are not a callable runtime service.

See the [private-interface plan](../hypervisor/PRIVATE-INTERFACE-PLAN.md) and
[build documentation](README.md). Previously compiled clients are unsupported and
can fault when they issue retired calls. Do not use them to detect a runtime.
