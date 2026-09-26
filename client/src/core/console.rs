//! An interactive prompt over one open process: type what to read and see it at once.
//!
//! Addresses are hexadecimal (`0x7ff6a0001000`, `7ff6a0001000`) or `module[+offset]` with a
//! hexadecimal offset (`client.dll+0x40`) that lies inside the image. They contain no spaces.

use std::{
    fmt::{self, Write as _},
    io::{self, Write},
    str::FromStr,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use svmvisor_live_reader::{ErrorKind, Module, Result};

use crate::process::Process;

/// Bytes `dump` shows when no length is given.
const DUMP_BYTES: usize = 64;
/// Most bytes one `dump` shows.
const MAX_DUMP_BYTES: usize = 64 * 1024;
/// Wait between the reads of a `watch` that names no interval of its own.
const WATCH_INTERVAL: Duration = Duration::from_millis(500);
/// Slowest interval a `watch` may name, in milliseconds.
const MAX_WATCH_MILLIS: u64 = 60_000;
/// Every value type, by the name typed at the prompt.
const KINDS: [(&str, Kind); 10] = [
    ("u8", Kind::U8),
    ("u16", Kind::U16),
    ("u32", Kind::U32),
    ("u64", Kind::U64),
    ("i8", Kind::I8),
    ("i16", Kind::I16),
    ("i32", Kind::I32),
    ("i64", Kind::I64),
    ("f32", Kind::F32),
    ("f64", Kind::F64),
];
const HELP: &str = "\
  modules                      list the loaded modules and refresh the names addresses can use
  read <address> [type]        read one value: u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 (default u64)
  dump <address> [length]      hex dump, length in bytes as decimal or 0x-hex (default 64)
  watch <address> [type] [ms]  print one value every 500 ms, or every `ms`, until Enter
  help, quit
  Addresses: 0x7ff6a0001000, or module[+offset] such as client.dll+0x40.";

/// One line typed at the prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Help,
    Modules,
    Read(u64, Kind),
    Dump(u64, usize),
    Watch(u64, Kind, Duration),
    Quit,
}

impl Command {
    /// `None` for a blank line; `Err` says what is wrong with the line.
    fn parse(line: &str, modules: &[Module]) -> Result<Option<Self>, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        let command = match words.as_slice() {
            [] => return Ok(None),
            ["help" | "?"] => Self::Help,
            ["modules"] => Self::Modules,
            ["quit" | "exit"] => Self::Quit,
            ["read", address, rest @ ..] if rest.len() <= 1 => {
                Self::Read(locate(address, modules)?, value_kind(rest.first().copied())?)
            }
            ["watch", address, rest @ ..] if rest.len() <= 2 => {
                let address = locate(address, modules)?;
                let kind = value_kind(rest.first().copied())?;
                let interval =
                    rest.get(1).map_or(Ok(WATCH_INTERVAL), |text| interval_millis(text))?;
                Self::Watch(address, kind, interval)
            }
            ["dump", address, rest @ ..] if rest.len() <= 1 => {
                let length = rest.first().map_or(Ok(DUMP_BYTES), |length| dump_length(length))?;
                Self::Dump(locate(address, modules)?, length)
            }
            _ => return Err(format!("Cannot run `{}`; type help.", line.trim())),
        };
        Ok(Some(command))
    }
}

/// A value type a `read` or `watch` decodes, little-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

impl Kind {
    fn bytes(self) -> usize {
        match self {
            Self::U8 | Self::I8 => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
        }
    }

    /// Integers as hexadecimal and decimal, floats as decimal. `bytes` is `self.bytes()` long.
    fn format(self, bytes: &[u8]) -> String {
        let mut raw = [0u8; 8];
        raw[..bytes.len()].copy_from_slice(bytes);
        let unsigned = u64::from_le_bytes(raw);
        let width = self.bytes() * 2;
        let shift = 64 - 8 * self.bytes();
        match self {
            Self::U8 | Self::U16 | Self::U32 | Self::U64 => {
                format!("0x{unsigned:0width$X} ({unsigned})")
            }
            Self::I8 | Self::I16 | Self::I32 | Self::I64 => {
                let signed = ((unsigned << shift) as i64) >> shift;
                format!("0x{unsigned:0width$X} ({signed})")
            }
            Self::F32 => format!("{}", f32::from_bits(unsigned as u32)),
            Self::F64 => format!("{}", f64::from_bits(unsigned)),
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, _) = KINDS.iter().find(|(_, kind)| kind == self).expect("every kind is named");
        formatter.write_str(name)
    }
}

impl FromStr for Kind {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, String> {
        KINDS
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
            .map(|&(_, kind)| kind)
            .ok_or_else(|| format!("Unknown type {name}; use u8..u64, i8..i64, f32 or f64."))
    }
}

/// Runs the prompt until `quit` or the end of input. Unreadable addresses and mistyped lines are
/// reported and the prompt continues; the process exiting or the session failing ends it and is
/// returned.
pub fn run(process: &mut Process) -> Result<()> {
    let mut modules = match process.modules() {
        Ok(modules) => modules,
        Err(error) if is_fatal(error.kind()) => return Err(error),
        Err(error) => {
            println!("  modules unavailable: {error}");
            Vec::new()
        }
    };
    println!("{} modules loaded. Type help for commands.", modules.len());
    loop {
        print!("svmvisor> ");
        // A prompt that fails to flush still reads the line.
        let _ = io::stdout().flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).map_or(true, |read| read == 0) {
            return Ok(());
        }
        let command = match Command::parse(&line, &modules) {
            Ok(Some(command)) => command,
            Ok(None) => continue,
            Err(message) => {
                println!("  {message}");
                continue;
            }
        };
        let result = match command {
            Command::Help => {
                println!("{HELP}");
                Ok(())
            }
            Command::Modules => process.modules().map(|listed| {
                modules = listed;
                for module in &modules {
                    println!("  {:<32} 0x{:016X}  0x{:X}", module.name, module.base, module.size);
                }
            }),
            Command::Read(address, kind) => {
                let mut bytes = [0; 8];
                let bytes = &mut bytes[..kind.bytes()];
                process.read_into(address, bytes).map(|()| {
                    println!("  {} = {}", describe(address, &modules), kind.format(bytes));
                })
            }
            Command::Dump(address, length) => {
                process.read_bytes(address, length).map(|bytes| print!("{}", dump(address, &bytes)))
            }
            Command::Watch(address, kind, interval) => {
                watch(process, address, kind, interval, &modules)
            }
            Command::Quit => return Ok(()),
        };
        match result {
            Ok(()) => {}
            Err(error) if is_fatal(error.kind()) => return Err(error),
            Err(error) => println!("  {error}"),
        }
    }
}

/// Reads `address` every `interval`, one line per sample, until Enter is pressed. A sample that
/// cannot be read is reported as its own line and the watch continues; a fatal error ends it.
fn watch(
    process: &mut Process,
    address: u64,
    kind: Kind,
    interval: Duration,
    modules: &[Module],
) -> Result<()> {
    println!(
        "  watching {} as {kind} every {} ms; press Enter to stop.",
        describe(address, modules),
        interval.as_millis()
    );
    let (stop, stopped) = mpsc::channel();
    thread::spawn(move || {
        let _ = io::stdin().read_line(&mut String::new());
        let _ = stop.send(());
    });
    let started = Instant::now();
    let mut next = started;
    let mut number = 0u64;
    let mut bytes = [0; 8];
    let bytes = &mut bytes[..kind.bytes()];
    loop {
        number += 1;
        let read_started = Instant::now();
        let value = match process.read_into(address, bytes) {
            Ok(()) => kind.format(bytes),
            Err(error) if is_fatal(error.kind()) => {
                println!();
                return Err(error);
            }
            Err(error) => format!("unreadable: {error}"),
        };
        let read = read_started.elapsed();
        println!("{}", sample_line(number, started.elapsed(), &value, read));
        // The wait until the next sample is also the wait for Enter.
        next = next_sample(next, interval, Instant::now());
        match stopped.recv_timeout(next.saturating_duration_since(Instant::now())) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

/// Keep the normal cadence when on time; after an overrun, skip the backlog and
/// wait a full interval. Slow reads or console output must not trigger catch-up reads.
fn next_sample(previous: Instant, interval: Duration, now: Instant) -> Instant {
    let scheduled = previous + interval;
    if scheduled > now { scheduled } else { now + interval }
}

/// One `watch` line: the sample number, the time since the watch began, the value or its error,
/// and how long that read took.
fn sample_line(number: u64, elapsed: Duration, value: &str, read: Duration) -> String {
    format!(
        "  #{number:<6} +{:>9.3}s  {value:<44} {:.3} ms",
        elapsed.as_secs_f64(),
        read.as_secs_f64() * 1000.0
    )
}

/// True for failures that close the process or the session, which the prompt cannot outlive.
fn is_fatal(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::ProcessGone | ErrorKind::InvalidHandle | ErrorKind::SessionEnded)
}

/// `address` as hexadecimal, or `module[+offset]` with a hexadecimal offset inside the image.
fn locate(address: &str, modules: &[Module]) -> Result<u64, String> {
    let (name, offset) = match address.split_once('+') {
        Some((name, offset)) => (name, Some(offset)),
        None => (address, None),
    };
    let Some(module) = modules.iter().find(|module| module.name.eq_ignore_ascii_case(name)) else {
        return match offset {
            None if !name.contains('.') => hexadecimal(address),
            _ => Err(format!("No loaded module is named {name}; `modules` refreshes the list.")),
        };
    };
    let offset = offset.map_or(Ok(0), hexadecimal)?;
    module.address(offset).ok_or_else(|| {
        format!("{}+0x{offset:X} is outside its 0x{:X}-byte image.", module.name, module.size)
    })
}

fn hexadecimal(value: &str) -> Result<u64, String> {
    let digits = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    u64::from_str_radix(digits, 16)
        .map_err(|_| format!("{value} is not a hexadecimal address or offset."))
}

/// The type a `read` or `watch` decodes: the named one, or `u64` when none is named.
fn value_kind(name: Option<&str>) -> Result<Kind, String> {
    name.map_or(Ok(Kind::U64), |name| name.parse())
}

/// A `dump` length: decimal, or hexadecimal with `0x`, from 1 to [`MAX_DUMP_BYTES`].
fn dump_length(value: &str) -> Result<usize, String> {
    let length = match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        Some(digits) => usize::from_str_radix(digits, 16).ok(),
        None => value.parse().ok(),
    };
    length
        .filter(|length| (1..=MAX_DUMP_BYTES).contains(length))
        .ok_or_else(|| format!("Length must be 1..={MAX_DUMP_BYTES} bytes."))
}

/// A `watch` interval in milliseconds, from 1 to [`MAX_WATCH_MILLIS`].
fn interval_millis(value: &str) -> Result<Duration, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|&millis| (1..=MAX_WATCH_MILLIS).contains(&millis))
        .map(Duration::from_millis)
        .ok_or_else(|| format!("Interval must be 1..={MAX_WATCH_MILLIS} ms."))
}

/// `address` as `module+0xoffset` when it lies inside one of `modules`, else as hexadecimal.
fn describe(address: u64, modules: &[Module]) -> String {
    modules
        .iter()
        .find_map(|module| module.offset(address).map(|offset| (module, offset)))
        .map_or_else(
            || format!("0x{address:X}"),
            |(module, offset)| format!("{}+0x{offset:X}", module.name),
        )
}

/// Sixteen bytes a line: address, hexadecimal, then printable ASCII.
fn dump(address: u64, bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(16) * 86);
    for (index, line) in bytes.chunks(16).enumerate() {
        let line_address = address + index as u64 * 16;
        // Writing to String cannot fail; no formatting intermediate needs allocation.
        write!(text, "  {line_address:016X}  ").unwrap();
        for byte in line {
            write!(text, "{byte:02X} ").unwrap();
        }
        for _ in line.len()..16 {
            text.push_str("   ");
        }
        text.push(' ');
        for &byte in line {
            text.push(if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '.' });
        }
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modules() -> [Module; 2] {
        [
            Module { name: "game.exe".into(), base: 0x7ff6_0000_0000, size: 0x5000 },
            Module { name: "client.dll".into(), base: 0x7ffa_1000_0000, size: 0x2000 },
        ]
    }

    #[test]
    fn commands_parse_addresses_types_and_lengths() {
        let modules = modules();
        let parse = |line| Command::parse(line, &modules);
        assert_eq!(parse("  "), Ok(None));
        assert_eq!(parse("modules"), Ok(Some(Command::Modules)));
        assert_eq!(parse("read 0x1000"), Ok(Some(Command::Read(0x1000, Kind::U64))));
        assert_eq!(
            parse("read CLIENT.DLL+0x40 f32"),
            Ok(Some(Command::Read(0x7ffa_1000_0040, Kind::F32)))
        );
        assert_eq!(
            parse("watch game.exe i16"),
            Ok(Some(Command::Watch(0x7ff6_0000_0000, Kind::I16, WATCH_INTERVAL)))
        );
        assert_eq!(
            parse("watch client.dll+0x40 u32 25"),
            Ok(Some(Command::Watch(0x7ffa_1000_0040, Kind::U32, Duration::from_millis(25))))
        );
        assert_eq!(parse("dump 7ff6a000"), Ok(Some(Command::Dump(0x7ff6_a000, DUMP_BYTES))));
        assert_eq!(parse("dump client.dll 0x100"), Ok(Some(Command::Dump(0x7ffa_1000_0000, 256))));
        for line in [
            "read",
            "read 0x1000 u24",
            "read 0x1000 u8 extra",
            "read client.dll+0x2000",
            "read server.dll",
            "read xyz",
            "watch 0x1000 u64 0",
            "watch 0x1000 u64 60001",
            "watch 0x1000 u64 5ms",
            "watch 0x1000 u64 u8",
            "dump 0x1000 0",
            "dump 0x1000 65537",
            "jump",
        ] {
            assert!(parse(line).is_err(), "{line}");
        }
    }

    #[test]
    fn sample_lines_carry_the_number_time_value_and_cost() {
        assert_eq!(
            sample_line(12, Duration::from_millis(1512), "0x0 (0)", Duration::from_micros(412)),
            "  #12     +    1.512s  0x0 (0)                                      0.412 ms"
        );
    }

    #[test]
    fn late_watch_samples_skip_backlog_instead_of_requesting_immediate_reads() {
        let first = Instant::now();
        let interval = Duration::from_millis(10);
        assert_eq!(
            next_sample(first, interval, first + Duration::from_millis(3)),
            first + interval
        );
        let completed = first + Duration::from_millis(35);
        let next = next_sample(first, interval, completed);
        assert_eq!(next.duration_since(completed), interval);
        // Repeated reads longer than the interval still leave a wait after every sample.
        let completed = next + Duration::from_millis(25);
        assert_eq!(next_sample(next, interval, completed).duration_since(completed), interval);
        // An exactly missed deadline does not create a zero-duration catch-up wait either.
        assert_eq!(next_sample(first, interval, first + interval), first + interval * 2);
    }

    #[test]
    fn values_format_as_hexadecimal_and_decimal() {
        assert_eq!(Kind::U32.format(&0x118u32.to_le_bytes()), "0x00000118 (280)");
        assert_eq!(Kind::I8.format(&[0xfe]), "0xFE (-2)");
        assert_eq!(Kind::I64.format(&(-1i64).to_le_bytes()), "0xFFFFFFFFFFFFFFFF (-1)");
        assert_eq!(Kind::F32.format(&12.5f32.to_le_bytes()), "12.5");
        assert_eq!(Kind::F64.to_string(), "f64");
    }

    #[test]
    fn dumps_show_sixteen_bytes_a_line_and_places_name_their_module() {
        let bytes: Vec<u8> = (0..18).map(|index| b'A' + index).collect();
        assert_eq!(
            dump(0x1000, &bytes),
            "  0000000000001000  41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50  ABCDEFGHIJKLMNOP\n\
             \x20 0000000000001010  51 52                                            QR\n"
        );
        assert_eq!(describe(0x7ffa_1000_0040, &modules()), "client.dll+0x40");
        assert_eq!(describe(0x1000, &modules()), "0x1000");
    }

    #[test]
    fn dump_keeps_ascii_and_hex_columns_for_empty_partial_and_full_lines() {
        assert!(dump(0, &[]).is_empty());
        for length in [1, 15, 16, 17, MAX_DUMP_BYTES] {
            let bytes: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let text = dump(0x1000, &bytes);
            assert_eq!(text.lines().count(), length.div_ceil(16));
            for (line, source) in text.lines().zip(bytes.chunks(16)) {
                assert_eq!(line.len(), 69 + source.len());
                for (index, byte) in source.iter().enumerate() {
                    assert_eq!(&line[20 + index * 3..22 + index * 3], format!("{byte:02X}"));
                    let ascii = if byte.is_ascii_graphic() || *byte == b' ' { *byte } else { b'.' };
                    assert_eq!(line.as_bytes()[69 + index], ascii);
                }
            }
        }
    }
}
