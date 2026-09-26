# svmvisor

An experimental minimal AMD SVM hypervisor for one bare-metal Windows guest,
loaded by a PCIe option-ROM UEFI driver.

The native-hardware rewrite removes AVIC, the virtual APIC register model, the
physical IRQ bridge, cache replay, and the separate first-exit payload. Physical
interrupts, ordinary APIC operations, and cache MSRs remain hardware-owned.
Software INIT/SIPI routing remains to start the guest CPUs without resetting the
resident monitor. CPUID and CR3 execute natively; nested SVM is unsupported.

The unauthenticated local reader and ARM/QUERY experiment have been retired.
This interim build disables live reading. The rebuilt [client](client/README.md)
returns an explicit error before any native call. Bounded translation, process
validation and batch primitives remain available for offline tests.

The [private-interface plan](crates/hypervisor/PRIVATE-INTERFACE-PLAN.md) targets
an isolated analysis component on this PC. Authentication, trusted boot and DMA
isolation are still required before reading can resume under the kernel threat
model. Removing the old interfaces does not establish those protections or make
the hypervisor undetectable.

[IOMMU discovery](crates/hypervisor/IOMMU-DISCOVERY.md) adds bounded firmware
inventory and read-only state observation. DMA ownership and a protected client
remain subsequent work; discovery cannot enable the reader.
The complete historical report now has retained backing inside the monitor pool,
with guest CPU exclusion and read-only host mappings. This supplies lifetime,
not protection from DMA or fresh takeover evidence.
The [ownership preparation](crates/hypervisor/IOMMU-OWNERSHIP.md) adds offline
entry/command codecs, bounded table-image construction and host-walk checks. It
also adds permanent per-CPU configuration-route interception and bounded NPT
control-page denial construction. Real IOMMU control-page denial remains inactive
until hardware ownership and the Windows presentation are implemented.
Complete restricted DTE and basic interrupt-entry codecs now require explicit
interrupt behavior; they do not install a device policy.
One complete deny-default device table and empty command/event/completion backing
now reside in the retained pool, with CPU exclusion and read-only host mappings.
They remain uninstalled; the bounded offline queue never submits commands.

**Status:** the current control-preparation build deliberately stops on PCI data
I/O, ECAM writes, CF9 reset and route changes without an admitted effects policy.
It is an offline review artifact, not a compatible Windows deployment. Further
software and platform evidence are required before a normal Windows boot test;
previous boot results do not qualify this revision.

## Layout

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
cargo test -p svmvisor-hypervisor --lib --no-default-features --features resident-runtime --locked
cargo xtask resident --output target/native-resident/<fresh-name>
cargo xtask card-dev
```

`resident` and `card-dev` select `resident-runtime` with the reader and guest
experiment disabled. The retired `--entry-trial` flag is rejected.
Builds do not deploy automatically. `cargo xtask card-dev --flash` programs the
payload slot; power-cycle the target to test it. `cargo xtask card-snapshot` reads
card/boot records; this resident no longer exports live register or stop records.

See [hypervisor](crates/hypervisor/README.md) and [build tools](crates/xtask/README.md).
