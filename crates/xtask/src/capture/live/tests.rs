use super::*;

pub(super) fn arguments() -> Vec<String> {
    [
        "--live",
        "--local-runtime-v2",
        "--kernel",
        "kernel.exe",
        "--pdb",
        "kernel.pdb",
        "--kernel-root",
        "0x1000",
        "--list-head",
        "0x3000",
        "--physical-bits",
        "48",
        "--nxe",
        "true",
        "--page-1g",
        "true",
        "--max-nodes",
        "1",
        "--pid",
        "42",
        "--address",
        "0xaffc",
        "--length",
        "8",
        "--hex",
        "--max-calls",
        "10000",
        "--deadline-ms",
        "1000",
        "--response-ms",
        "100",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[test]
fn automatic_context_is_explicit_and_excludes_every_manual_context_flag() {
    let mut auto = arguments();
    let flags = ["--kernel-root", "--list-head", "--physical-bits", "--nxe", "--page-1g"];
    for key in flags {
        let index = auto.iter().position(|value| value == key).unwrap();
        auto.drain(index..index + 2);
    }
    assert!(LiveOptions::parse(&auto).is_err());
    auto.push("--auto-context".into());
    let options = LiveOptions::parse(&auto).unwrap();
    assert!(options.context.is_none());
    for (key, value) in flags.into_iter().zip(["0x1000", "0x3000", "48", "true", "true"]) {
        let mut invalid = auto.clone();
        invalid.extend([key.into(), value.into()]);
        assert!(LiveOptions::parse(&invalid).is_err(), "{key}");
    }
    auto.push("--auto-context".into());
    assert!(LiveOptions::parse(&auto).is_err());
}

#[test]
fn manual_context_and_limits_reach_the_library_configuration() {
    let options = LiveOptions::parse(&arguments()).unwrap();
    assert_eq!(
        options.context,
        Some(ManualContext {
            kernel_root: 0x1000,
            list_head: 0x3000,
            physical_bits: 48,
            nxe: true,
            page_1g: true,
        })
    );
    assert_eq!((options.pid, options.va, options.length, options.max_nodes), (42, 0xaffc, 8, 1));
    for (key, value) in
        [("--physical-bits", "60"), ("--kernel-root", "0x1001"), ("--list-head", "0x3004")]
    {
        let mut args = arguments();
        let position = args.iter().position(|arg| arg == key).unwrap();
        args[position + 1] = value.into();
        assert!(LiveOptions::parse(&args).is_err(), "{key}={value}");
    }
    let mut args = arguments();
    let position = args.iter().position(|arg| arg == "--pid").unwrap();
    args[position + 1] = "0x100000000".into();
    assert!(LiveOptions::parse(&args).is_err());
}

#[test]
fn explicit_live_and_complete_context_are_required_before_starting_bridge() {
    let args = arguments();
    assert!(LiveOptions::parse(&args[1..]).is_err());
    let options = LiveOptions::parse(&args).unwrap();
    assert_eq!(options.cpu, 0);
    let mut unacknowledged = args.clone();
    unacknowledged.retain(|arg| arg != "--local-runtime-v2");
    assert!(LiveOptions::parse(&unacknowledged).is_err());
    for key in ["--kernel-root", "--max-nodes", "--max-calls", "--deadline-ms", "--response-ms"] {
        let mut args = arguments();
        let position = args.iter().position(|arg| arg == key).unwrap();
        args[position + 1] = "0".into();
        assert!(LiveOptions::parse(&args).is_err(), "{key}");
    }
}

#[test]
fn session_mode_requires_context_and_excludes_one_shot_output() {
    let mut args = arguments();
    for key in ["--pid", "--address", "--length"] {
        let position = args.iter().position(|arg| arg == key).unwrap();
        args.drain(position..position + 2);
    }
    args.retain(|arg| arg != "--hex");
    args.push("--stdio".into());
    assert!(LiveOptions::parse(&args).unwrap().stdio);
    for addition in [vec!["--hex"], vec!["--pid", "42"], vec!["--output", "sample.bin"]] {
        let mut invalid = args.clone();
        invalid.extend(addition.into_iter().map(str::to_string));
        assert!(LiveOptions::parse(&invalid).is_err());
    }
    for key in [
        "--kernel",
        "--pdb",
        "--kernel-root",
        "--list-head",
        "--physical-bits",
        "--nxe",
        "--page-1g",
        "--max-nodes",
        "--max-calls",
        "--deadline-ms",
        "--response-ms",
    ] {
        let mut invalid = args.clone();
        let position = invalid.iter().position(|arg| arg == key).unwrap();
        invalid.drain(position..position + 2);
        assert!(LiveOptions::parse(&invalid).is_err(), "{key}");
    }
}
