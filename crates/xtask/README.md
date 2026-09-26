# xtask

The one host-side entry point of the build pipeline. `.cargo/config.toml`
aliases it, so from anywhere in the workspace:

```powershell
cargo xtask resident --output target/native-resident/<fresh-name>
cargo xtask sources
cargo xtask card-dev | card-snapshot | card-loader-dev   # see "Card development loop"
cargo xtask rompack --input <driver.efi> --output <driver.rom> ...   # see "cargo xtask rompack"
```

Std-only apart from `sha2`; nothing here runs on the target. Only
`card-dev --flash` and a live `card-snapshot` reach hardware, through the
scripts in `firmware/card`.

## `cargo xtask resident`

Builds the production native-resident image and audits what was actually
linked. The output directory must not exist; it keeps every artifact and one
`<step>.log` per tool invocation, also when a step fails.

1. Hash and copy every build input into `source/` (`source-manifest.json`).
2. `cargo rustc --locked --no-default-features --lib --features resident-runtime` the `crates/hypervisor` staticlib for `x86_64-unknown-none`
   (`-C relocation-model=static -C code-model=small`) -> `payload.a`.
3. `clang --target=x86_64-unknown-none` assembles `runtime.S`, `nmi.S` and
   `fault.S` from `crates/hypervisor/src/firmware/native/resident/`.
4. `ld.lld --gc-sections --emit-relocs -T crates/hypervisor/payload.ld`
   -> `payload.elf`; `llvm-objcopy -O binary` -> `payload.bin`.
5. Package the retained relocations (`src/relocations.rs`) -> `payload.reloc`,
   the `SVMRELO1` container that `crates/card-abi/src/package.rs` loads
   and `crates/hypervisor/build.rs` embeds through `SVMVISOR_RESIDENT_PAYLOAD`.
6. Audit the linked payload (`src/audit.rs`): no undefined symbols
   (`llvm-nm`); the required resident entry and world-switch symbols are present,
   and retired local-reader/entry-trial exports are absent;
   over the `llvm-objdump` disassembly, no FP/SIMD/xstate
   instruction, debug registers touched only by the exact DR0-3 reset helper,
   all 256 host fault frames, the capture sequence, SYS_CFG selection before
   physical CPUID/MSR sampling, the returning NMI gate and
   the #SX shape.
7. `cargo build --locked --no-default-features -p svmvisor-hypervisor --target x86_64-unknown-uefi
   --release --bin svmvisor-hypervisor`
   -> `driver.efi`, which must be an EFI runtime driver (PE subsystem 12).
8. Audit `physical.S` (the copied AP wait span lives in `.rdata`, has no COFF
   relocations and is at most 3840 bytes) and disassemble `boot.S`.
9. Re-hash the inputs; any change during the build fails it. Write
   `summary.json` (profile, audit results, SHA-256 of every artifact).

`firmware/card/verify-resident-build.py` consumes the output directory.

The single supported payload disables live reading and the guest experiment:

```powershell
cargo xtask resident --output target/native-resident/<fresh-name>
cargo xtask card-dev
```

The second command packages the card payload and runs offline flash checks. It flashes
only with `--flash`. Both commands select `resident-runtime` and disable default
features. The retired `--entry-trial` flag is rejected before building or flashing.
`summary.json` records `payload_features: "resident-runtime"`, `entry_trial: false`,
`reader_enabled: false` and `authenticated_reader: false`; `card-dev.json` records
the same disabled service status. The verifier rejects a mismatched profile or
retired service export. These checks do not establish authenticated reading.

`cargo xtask sources` prints the current source manifest, the same JSON a
build records as `source-manifest.json`.

The resident payload is the only hypervisor build. The build commands do not execute SVM,
boot Windows, flash the card, or establish hardware compatibility.

## `cargo xtask live-read`

`live-read --help` explains that the direct reader is disabled. Every execution
request, including old acknowledgements and stdio flags, returns an explicit error
before opening caller files or issuing a native call. `entry-trial` is also retired.

The [reader library](../live-reader/README.md) and added
[client library](../../client/README.md) report the same unavailable state. The
client's existing picker can display that error. The same-PC protected replacement
is specified in the [private-interface plan](../hypervisor/PRIVATE-INTERFACE-PLAN.md);
no authenticated runtime service is implemented yet.

Card snapshots remain separate boot/card diagnostics. The resident publishes no
live registers or progress. After the collective stop barrier it may publish a
closed coarse reason category (phase 15h, detail 8); private fault details stay
private. Offline builds and tests execute no live VMMCALL and do not establish
deployment or hardware privacy.

## `cargo xtask rompack`

```powershell
cargo xtask rompack --input <driver.efi> --output <driver.rom> `
    --vendor <hex> --device <hex> --class <hex> `
    [--memory-output <driver.mem> --memory-size <bytes>]
```

Wraps one uncompressed PE32+ EFI image in a PCI Firmware 3.0 option-ROM image
(the layout of EDK2 `EfiRom` in its default single-image mode) and, when both
memory options are given, writes the ROM as a `$readmemh` file of
little-endian 32-bit words padded with `0xff` to `--memory-size`. The output
depends only on the input bytes and the three IDs. `--vendor`, `--device` and
`--class` are hexadecimal with or without `0x`; `--memory-size` is decimal, or
hexadecimal with `0x`. `firmware/card/build-card.ps1` runs this command for the
card's 32 KiB ROM (`--memory-size 32768 --vendor 0x10ee --device 0x0666
--class 0xff0000`). This was the `svmvisor-rompack` crate; the arguments and
the output bytes are unchanged.

## Card development loop

For a card running the development loader (`card-resident-dev-loader`, see
[../../firmware/card/README.md](../../firmware/card/README.md), "Fast iteration"):

```powershell
cargo xtask card-dev [--flash] [--adapter-khz N]
cargo xtask card-snapshot [--input <log>] [--manifest <manifest.json>]
cargo xtask card-loader-dev
```

* `card-dev` runs the resident build above (in-process) into
  `target/card-dev/<utc>-<id>/resident`. This board always allocates the runtime
  below 1 GiB. It packages the payload slot with
  `firmware/card/package-payload.py --resident` into `payload/`, runs
  `verify-resident-build.py` and the offline `flash-card.ps1 -Action
  CheckPayload`, then prints the header digest, sizes, the slot sectors and the
  exact flash command. It writes `card-dev.json` and the text pointer
  `target/card-dev/latest`. Only with `--flash` does it run `flash-card.ps1
  -Action ProgramPayload -ConfirmFlash` (`--adapter-khz`, default 1000,
  100..30000): that is the only hardware access, and nothing is activated.
* `card-snapshot` runs `firmware/card/read_snapshot.py` (`--live` unless
  `--input` is given; its other options pass through) with `--output-dir
  target/card-snapshots/<utc>-<id> --summary`, and updates
  `target/card-snapshots/latest`. `--live` reads the card over JTAG.
* `card-loader-dev` builds the development loader (`--package
  svmvisor-card-loader --profile rom --features card-resident-dev-loader
  --target x86_64-unknown-uefi`) and packs the 32 KiB
  option ROM in-process (`src/rompack.rs`) with the same values
  `firmware/card/build-card.ps1` passes to `cargo xtask rompack`, into
  `target/card-dev/loader/<utc>-<id>/`.
  `build-card.ps1 -DevLoader -BuildFpga` then produces the one bitstream.

Needs `python` and a PowerShell host (`pwsh`, else `powershell`) on `PATH`.

## Required tools on `PATH`

* `clang`, `ld.lld`, `llvm-objcopy`, `llvm-nm`, `llvm-objdump` (LLVM)
* `cargo` with the Rust targets `x86_64-unknown-none` and
  `x86_64-unknown-uefi` (`rustup target add x86_64-unknown-none x86_64-unknown-uefi`)

## Tests

```powershell
cargo test -p xtask
```

covers the card-loop argument, timestamp and header helpers, the option-ROM packager, the relocation packager on synthetic ELF fixtures, every audit on
passing and mutated disassembly, and the JSON writer against a Python-generated
reference (`src/expected-json.txt`).

## GMET entry trial

The Windows one-shot client is documented in [ENTRY-TRIAL.md](ENTRY-TRIAL.md).
Use `cargo xtask entry-trial --help` for its explicit live invocation.
