# svmvisor

An experimental minimal AMD SVM hypervisor for one bare-metal Windows guest,
loaded by a PCIe option-ROM UEFI driver.

The native-hardware rewrite removes AVIC, the virtual APIC register model, the
physical IRQ bridge, cache replay, and the separate first-exit payload. Physical
interrupts, ordinary APIC operations, and cache MSRs remain hardware-owned.
Software INIT/SIPI routing remains to start the guest CPUs without resetting the
resident monitor. CPUID and CR3 execute natively; nested SVM is unsupported.

Same-PC process reads use the [local VMMCALL batch interface](LOCAL-READ.md).
The hypervisor performs process revalidation, virtual translation and memory reads;
the client supplies discovery/profile evidence and caller-owned result buffers.
USB and PCIe BAR transport are outside this local read path.

Process reads use monitor-side copies into validated client buffers. They do not
install a client aperture, modify target mappings, or require the GMET entry trial.
The separate entry-trial diagnostic remains available; experimental memory-window
code has been retired. Reads are best-effort observations, not atomic snapshots.

**Status:** this rewrite needs a fresh hardware boot test. Previous Windows boot
results apply to the removed virtual interrupt/cache backend, not this revision.

## Layout

- `client`: [Windows process picker and read-only console](client/README.md), with memory capture and address diagnostics.
- `crates/hypervisor`: the single hypervisor crate. `firmware/` owns UEFI boot,
  `host/resident/` owns the runtime, and `reader/` owns bounded memory reads.
  Its UEFI binary embeds its audited resident image, linked with `payload.ld`.
- `crates/card-abi`, `crates/card-loader`: card protocol and option-ROM loader.
- `crates/xtask`: build, linked-code audit, packaging and host tools.
- `firmware/card`: card RTL, transport, flashing and diagnostic tools.
- `docs`: indexed hardware manuals.

## Build and validate

```powershell
cargo test --workspace
cargo test -p svmvisor-hypervisor --features resident-runtime
cargo xtask resident --output target/native-resident/<fresh-name>
cargo xtask card-dev
```

Builds do not deploy automatically. `cargo xtask card-dev --flash` programs the
payload slot; power-cycle the target to test it. `cargo xtask card-snapshot` reads
its diagnostic records.

See [hypervisor](crates/hypervisor/README.md) and [build tools](crates/xtask/README.md).
