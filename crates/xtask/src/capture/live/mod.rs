//! Explicit live process reads through `svmvisor-live-reader`, as a one-shot or stdio session.

use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant},
};

use svmvisor_card_abi::batch::MAX_DATA_BYTES;
use svmvisor_hypervisor::memory::address::{PAGE_BYTES, is_canonical_48};
use svmvisor_hypervisor::reader::{paging::PagingConfig, process::MAX_PROCESS_NODES};
use svmvisor_live_reader::{Config, Svm};

use crate::capture::command::{parse_bool, parse_number};

mod session;

const USAGE: &str = "usage: cargo xtask live-read --live --local-runtime-v2 [--cpu <0..31>]
  --kernel <ntoskrnl.exe> --pdb <ntkrnlmp.pdb>
  (--auto-context | --kernel-root <PML4-GPA> --list-head <sentinel-VA>
    --physical-bits <32..52> --nxe <true|false> --page-1g <true|false>)
  --max-nodes <1..4096>
  (--stdio | --pid <PID> --address <VA> --length <1..4096> (--output <new-file> | --hex))
  --max-calls <1..1000000> --deadline-ms <1..3600000> --response-ms <1..60000>
  [--discovery-ms <1..3600000>] [--sample-ms <1..60000>] (stdio only)

--local-runtime-v2 acknowledges that this boot runs the redesigned local VMMCALL runtime.
It is required: probing a legacy runtime can stop the target machine. This flag is an operator
acknowledgement, not safe runtime absence detection. Do not use it before deploying that runtime.
The calling thread is pinned to processor group zero, CPU zero by default.

--stdio accepts {id,pid,address,length}, or {id,pid,ranges:[{address,length},...]}, with
0x-prefixed address strings, up to eight ranges and 4096 total bytes. One discovery and Bind
precede repeated resident Sample operations; the resident validates identity before and after.
Samples are best-effort observations, not atomic snapshots. Any failure ends the session and
publishes no partial data. No driver, USB or JTAG transport is used for sampling.
Kernel/PDB and supplied root/list context must match the running Windows boot.
--auto-context validates a fresh caller-root observation against the exact kernel profile.
It requires the optional context API and readable kernel metadata through that root; KPTI
roots lacking those mappings are refused. It does not cache historical kernel roots.
Programs should use the svmvisor-live-reader library directly; this command wraps it.
Exit codes: 0 complete, 1 runtime/profile/read/output failure, 2 arguments.";

/// Caller-supplied kernel context, in place of `--auto-context`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManualContext {
    kernel_root: u64,
    list_head: u64,
    physical_bits: u8,
    nxe: bool,
    page_1g: bool,
}

struct LiveOptions {
    stdio: bool,
    cpu: u16,
    kernel: PathBuf,
    pdb: PathBuf,
    context: Option<ManualContext>,
    max_nodes: usize,
    pid: u32,
    va: u64,
    length: usize,
    output: Option<PathBuf>,
    max_calls: u64,
    deadline: Duration,
    response_timeout: Duration,
    discovery_timeout: Duration,
    sample_timeout: Duration,
}

impl LiveOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let (mut live, mut hex, mut stdio, mut local_runtime, mut auto_context) =
            (false, false, false, false, false);
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            if matches!(
                arg.as_str(),
                "--live" | "--hex" | "--stdio" | "--local-runtime-v2" | "--auto-context"
            ) {
                let flag = match arg.as_str() {
                    "--live" => &mut live,
                    "--hex" => &mut hex,
                    "--stdio" => &mut stdio,
                    "--auto-context" => &mut auto_context,
                    _ => &mut local_runtime,
                };
                if *flag {
                    return Err(format!("duplicate {arg}"));
                }
                *flag = true;
                continue;
            }
            if !matches!(
                arg.as_str(),
                "--cpu"
                    | "--kernel"
                    | "--pdb"
                    | "--kernel-root"
                    | "--list-head"
                    | "--physical-bits"
                    | "--nxe"
                    | "--page-1g"
                    | "--max-nodes"
                    | "--pid"
                    | "--address"
                    | "--length"
                    | "--output"
                    | "--max-calls"
                    | "--deadline-ms"
                    | "--response-ms"
                    | "--discovery-ms"
                    | "--sample-ms"
            ) {
                return Err(format!("unknown argument {arg}"));
            }
            let value = rest.next().ok_or_else(|| format!("{arg} needs a value"))?;
            if value.is_empty() || value.starts_with("--") {
                return Err(format!("{arg} needs a value"));
            }
            if values.insert(arg.as_str(), value.as_str()).is_some() {
                return Err(format!("duplicate {arg}"));
            }
        }
        if !local_runtime {
            return Err("--local-runtime-v2 must acknowledge the redesigned runtime is booted; legacy VMMCALL can stop the machine".into());
        }
        if !live {
            return Err("--live is required; no VMMCALL was issued".into());
        }
        let required = |key| values.get(key).copied().ok_or_else(|| format!("{key} is required"));
        let number = |key| parse_number(required(key)?).map_err(|e| format!("{key}: {e}"));
        let bounded = |key, maximum| {
            let value = number(key)?;
            if value == 0 || value > maximum {
                return Err(format!("{key} must be 1..{maximum}"));
            }
            Ok(value)
        };
        let context = if auto_context {
            if ["--kernel-root", "--list-head", "--physical-bits", "--nxe", "--page-1g"]
                .iter()
                .any(|key| values.contains_key(key))
            {
                return Err("--auto-context excludes all five manual context flags".into());
            }
            None
        } else {
            let physical_bits = u8::try_from(number("--physical-bits")?)
                .map_err(|_| "--physical-bits must be 32..52")?;
            let (nxe, page_1g) =
                (parse_bool(required("--nxe")?)?, parse_bool(required("--page-1g")?)?);
            PagingConfig::new(physical_bits, nxe, page_1g)
                .map_err(|_| "--physical-bits must be 32..52")?;
            let kernel_root = number("--kernel-root")?;
            if kernel_root == 0
                || kernel_root & (PAGE_BYTES as u64 - 1) != 0
                || kernel_root >> physical_bits != 0
            {
                return Err(
                    "--kernel-root must be nonzero, aligned and within physical width".into()
                );
            }
            let list_head = number("--list-head")?;
            if list_head == 0
                || list_head & 7 != 0
                || !is_canonical_48(list_head)
                || list_head.checked_add(15).is_none_or(|last| !is_canonical_48(last))
            {
                return Err("--list-head must be an aligned canonical sentinel VA".into());
            }
            Some(ManualContext { kernel_root, list_head, physical_bits, nxe, page_1g })
        };
        if stdio
            && (hex
                || ["--pid", "--address", "--length", "--output"]
                    .iter()
                    .any(|key| values.contains_key(key)))
        {
            return Err("--stdio excludes --pid, --address, --length, --output and --hex".into());
        }
        let length = if stdio { 1 } else { bounded("--length", MAX_DATA_BYTES as u64)? as usize };
        let va = if stdio { 0 } else { number("--address")? };
        if !is_canonical_48(va)
            || va.checked_add(length as u64 - 1).is_none_or(|last| !is_canonical_48(last))
        {
            return Err("virtual range must be nonwrapping and canonical".into());
        }
        let pid = if stdio {
            0
        } else {
            u32::try_from(bounded("--pid", u64::from(u32::MAX))?)
                .map_err(|_| "--pid must fit in 32 bits")?
        };
        let output = values.get("--output").map(PathBuf::from);
        if !stdio && (hex == output.is_some() || hex && length > 256) {
            return Err("choose --output or --hex (hex maximum 256 bytes)".into());
        }
        if !stdio && (values.contains_key("--discovery-ms") || values.contains_key("--sample-ms")) {
            return Err("--discovery-ms and --sample-ms require --stdio".into());
        }
        let discovery_ms = if values.contains_key("--discovery-ms") {
            bounded("--discovery-ms", 3_600_000)?
        } else {
            600_000
        };
        let sample_ms = if values.contains_key("--sample-ms") {
            bounded("--sample-ms", 60_000)?
        } else {
            10_000
        };
        let cpu = values.get("--cpu").map(|value| parse_number(value)).transpose()?.unwrap_or(0);
        if cpu >= 32 {
            return Err("--cpu must be 0..31".into());
        }
        Ok(Self {
            stdio,
            cpu: cpu as u16,
            kernel: PathBuf::from(required("--kernel")?),
            pdb: PathBuf::from(required("--pdb")?),
            context,
            max_nodes: bounded("--max-nodes", MAX_PROCESS_NODES as u64)? as usize,
            pid,
            va,
            length,
            output,
            max_calls: bounded("--max-calls", 1_000_000)?,
            deadline: Duration::from_millis(bounded("--deadline-ms", 3_600_000)?),
            response_timeout: Duration::from_millis(bounded("--response-ms", 60_000)?),
            discovery_timeout: Duration::from_millis(discovery_ms),
            sample_timeout: Duration::from_millis(sample_ms),
        })
    }

    /// The library settings these limits describe; `remaining` bounds the whole session.
    fn reader_config(&self, remaining: Duration) -> Config {
        let config = Config::new(&self.kernel, &self.pdb)
            .cpu(self.cpu)
            .max_nodes(self.max_nodes)
            .max_calls(self.max_calls)
            .session_timeout(remaining)
            .response_timeout(self.response_timeout)
            .open_timeout(self.discovery_timeout)
            .read_timeout(self.sample_timeout);
        match self.context {
            Some(manual) => config.manual_context(
                manual.kernel_root,
                manual.list_head,
                manual.physical_bits,
                manual.nxe,
                manual.page_1g,
            ),
            None => config,
        }
    }
}

/// Opens the live session after the operator's `--local-runtime-v2` acknowledgement.
fn connect(options: &LiveOptions, remaining: Duration) -> Result<Svm, String> {
    // SAFETY: LiveOptions::parse refuses to proceed without --live --local-runtime-v2, the
    // operator's statement that this boot runs the redesigned runtime.
    unsafe { Svm::connect(options.reader_config(remaining)) }.map_err(|error| error.to_string())
}

fn report_context(svm: &Svm) {
    if let Some(context) = svm.kernel_context() {
        match context.kernel_base {
            Some(base) => eprintln!(
                "context=automatic-validated kernel_base={base:#x} system_root={:#x} list_head={:#x}",
                context.kernel_root, context.process_list
            ),
            None => eprintln!(
                "context=caller-supplied system_root={:#x} list_head={:#x}",
                context.kernel_root, context.process_list
            ),
        }
    }
}

pub(crate) fn command(args: &[String]) -> ExitCode {
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match LiveOptions::parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let started = Instant::now();
    let result = if options.stdio { session::execute(options, started) } else { execute(&options) };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(options: &LiveOptions) -> Result<u8, String> {
    let mut output = options
        .output
        .as_ref()
        .map(|path| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|error| format!("create {}: {error}", path.display()))
        })
        .transpose()?;
    eprintln!(
        "consistency=best-effort context={} transport=local-vmmcall no-snapshot=true",
        if options.context.is_none() { "automatic-requested" } else { "caller-supplied" }
    );
    let mut svm = connect(options, options.deadline)?;
    let process = svm.open_process(options.pid).map_err(|error| error.to_string())?;
    report_context(&svm);
    let mut bytes = vec![0; options.length];
    svm.read_process_memory(process, options.va, &mut bytes).map_err(|error| error.to_string())?;
    let calls = svm.calls();
    drop(svm);
    if let Some(output) = output.as_mut() {
        output
            .write_all(&bytes)
            .and_then(|()| output.flush())
            .map_err(|error| format!("output failed (may contain prefix): {error}"))?;
    } else {
        for chunk in bytes.chunks(16) {
            println!(
                "{}",
                chunk.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
            );
        }
    }
    eprintln!(
        "status=sampled-complete consistency=best-effort requested={} bytes_read={} batch_calls={}",
        options.length,
        bytes.len(),
        calls
    );
    Ok(0)
}

#[cfg(test)]
mod tests;
