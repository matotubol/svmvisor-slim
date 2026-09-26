use super::*;

#[test]
fn retired_options_cannot_enable_reading_or_start_stdio() {
    for args in [
        vec![],
        vec!["--live", "--local-runtime-v2"],
        vec!["--live", "--local-runtime-v2", "--stdio"],
        vec!["--hex", "--auto-context", "--kernel", "missing.exe"],
        vec!["--cpu", "invalid", "--output"],
        vec!["--help", "--live"],
    ] {
        let args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
        let mut output = Vec::new();
        let mut errors = Vec::new();
        assert_eq!(run(&args, &mut output, &mut errors), ExitCode::FAILURE);
        assert!(output.is_empty());
        assert_eq!(String::from_utf8(errors).unwrap(), format!("error: {DISABLED}\n"));
    }
}

#[test]
fn disabled_command_does_not_create_requested_output() {
    let path = std::env::temp_dir().join(format!(
        "svmvisor-retired-reader-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    assert!(!path.exists());
    let args = vec![
        "--live".into(),
        "--local-runtime-v2".into(),
        "--output".into(),
        path.to_string_lossy().into_owned(),
    ];
    assert_eq!(run(&args, &mut Vec::new(), &mut Vec::new()), ExitCode::FAILURE);
    assert!(!path.exists());
}

#[test]
fn help_reports_disabled_state_without_connection_instructions() {
    for help in ["--help", "-h"] {
        let mut output = Vec::new();
        let mut errors = Vec::new();
        assert_eq!(run(&[help.into()], &mut output, &mut errors), ExitCode::SUCCESS);
        assert_eq!(String::from_utf8(output).unwrap(), format!("{USAGE}\n"));
        assert!(errors.is_empty());
    }
}
