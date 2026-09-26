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
2. `cargo rustc --lib --features resident-runtime` the `crates/hypervisor` staticlib for `x86_64-unknown-none`
   (`-C relocation-model=static -C code-model=small`) -> `payload.a`.
3. `clang --target=x86_64-unknown-none` assembles `runtime.S`, `nmi.S` and
   `fault.S` from `crates/hypervisor/src/firmware/native/resident/`.
4. `ld.lld --gc-sections --emit-relocs -T crates/hypervisor/payload.ld`
   -> `payload.elf`; `llvm-objcopy -O binary` -> `payload.bin`.
5. Package the retained relocations (`src/relocations.rs`) -> `payload.reloc`,
   the `SVMRELO1` container that `crates/card-abi/src/package.rs` loads
   and `crates/hypervisor/build.rs` embeds through `SVMVISOR_RESIDENT_PAYLOAD`.
6. Audit the linked payload (`src/audit.rs`): no undefined symbols
   (`llvm-nm`); the continuing producer's entry and read-service
   symbols are present and the one-shot experiment's entry symbols are
   absent; over the `llvm-objdump` disassembly, no FP/SIMD/xstate
   instruction, debug registers touched only by the exact DR0-3 reset helper,
   all 256 host fault frames, the capture sequence, the returning NMI gate and
   the #SX shape.
7. `cargo build --locked -p svmvisor-hypervisor --target x86_64-unknown-uefi
   --release --bin svmvisor-hypervisor`
   -> `driver.efi`, which must be an EFI runtime driver (PE subsystem 12).
8. Audit `physical.S` (the copied AP wait span lives in `.rdata`, has no COFF
   relocations and is at most 3840 bytes) and disassemble `boot.S`.
9. Re-hash the inputs; any change during the build fails it. Write
   `summary.json` (profile, audit results, SHA-256 of every artifact).

`firmware/card/verify-resident-build.py` consumes the output directory.

The GMET/#PF entry experiment is part of this workspace and is selected explicitly:

```powershell
cargo xtask resident --output target/native-resident/<fresh-name> --entry-trial
cargo xtask card-dev --entry-trial
```

The second command builds and packages the experimental card payload and runs offline
flash checks. It does not flash without `--flash`. Both commands select
`native-entry-trial`; the experiment remains dormant until its explicit VMMCALL ARM.
The linked-symbol audit requires the experiment's request/final/complete handlers in
this profile and forbids them in a standard build. `summary.json` records `entry_trial`
and `payload_features`; `card-dev.json` also records `entry_trial`. A later standard
build does not contain the experiment, even when built from this merged workspace.

`cargo xtask sources` prints the current source manifest, the same JSON a
build records as `source-manifest.json`.

The resident payload is the only hypervisor build. The build commands do not execute SVM,
boot Windows, flash the card, or establish hardware compatibility.

## `cargo xtask live-read`

`live-read` is a command-line wrapper around
[`svmvisor-live-reader`](../live-reader/README.md), which programs should link
directly. `cargo xtask live-read --help` describes local VMMCALL process batches. It requires
`--live --local-runtime-v2`, matching kernel/PDB files, and finite node/call/time
limits. Select `--auto-context` for bounded current-boot discovery, or supply all
five explicit root/list/paging context flags. Automatic discovery requires the
optional Context command and readable kernel mappings through the caller's root;
it stops on inconsistent observations without retrying. The runtime flag
acknowledges that the redesigned runtime is booted: probing the legacy runtime can
stop the target. It is not safe runtime absence detection.

`--stdio` keeps one pinned native session. Discovery and binding happen once;
steady-state samples move translation and identity checks into the resident.
Inputs accept a single `address,length` pair or up to eight `ranges`, totaling at
most 4096 bytes. Any failure ends the session and discards the whole sample.
`--cpu` selects a processor in group zero (default zero, maximum 31).

The [Rust desktop client](../../client/README.md) invokes this mode directly.
JTAG/FT601 scripts remain separate diagnostic tools. The local reader does not
launch them or require a Windows driver. Offline builds and tests execute no live
VMMCALL and do not establish runtime deployment or measured hardware performance.

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
