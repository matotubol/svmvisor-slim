//! Fail-stop local process sampling over bounded JSON lines and one resident binding.

use std::{
    io::{self, BufRead, Read, Write},
    sync::mpsc,
    thread,
    time::Instant,
};

use serde_json::{Value, json};
use svmvisor_card_abi::batch::{MAX_DATA_BYTES, MAX_RANGES};
use svmvisor_hypervisor::memory::address::is_canonical_48;

use crate::capture::live::{LiveOptions, connect, report_context};

const MAX_LINE_BYTES: u64 = 4096;

/// One decoded `{id,pid,...}` line: the ranges to read, in reply order.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    id: u64,
    pid: u32,
    ranges: Vec<(u64, usize)>,
}

pub(super) fn execute(options: LiveOptions, started: Instant) -> Result<u8, String> {
    let deadline = started.checked_add(options.deadline).ok_or("invalid session deadline")?;
    let remaining =
        deadline.checked_duration_since(Instant::now()).ok_or("session deadline reached")?;
    let mut svm = connect(&options, remaining)?;
    let initialization_ms = started.elapsed().as_secs_f64() * 1000.0;
    let (sender, requests) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            let result = read_line(&mut input);
            let done = !matches!(result, Ok(Some(_)));
            if sender.send(result).is_err() || done {
                break;
            }
        }
    });
    let mut process = None;
    let mut previous_id = None;
    let mut output = io::stdout().lock();
    loop {
        let remaining = deadline.checked_duration_since(Instant::now());
        let line = remaining
            .ok_or_else(|| "session deadline reached".to_string())
            .and_then(|remaining| {
                requests
                    .recv_timeout(remaining)
                    .map_err(|error| format!("session input timeout/disconnect: {error}"))
            })
            .and_then(|result| result);
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(0),
            Err(error) => {
                write_reply(&mut output, json!({"id":null,"status":"error","error":error}))?;
                return Ok(1);
            }
        };
        let id = serde_json::from_str::<Value>(&line).ok().and_then(|value| value["id"].as_u64());
        let result = decode_request(&line).and_then(|request| {
            if previous_id.is_some_and(|previous| request.id <= previous) {
                return Err("request IDs must strictly increase".into());
            }
            let first = process.is_none();
            let mut discovery_ms = 0.0;
            let mut discovery_calls = 0;
            if first {
                eprintln!(
                    "phase=discovery state=started pid={} limit_ms={}",
                    request.pid,
                    options.discovery_timeout.as_millis()
                );
                let discovery_started = Instant::now();
                let calls_before = svm.calls();
                process =
                    Some(svm.open_process(request.pid).map_err(|error| error.to_string())?);
                discovery_ms = discovery_started.elapsed().as_secs_f64() * 1000.0;
                discovery_calls = svm.calls() - calls_before;
                report_context(&svm);
                eprintln!(
                    "phase=discovery state=complete calls={discovery_calls} elapsed_ms={discovery_ms:.3}"
                );
            }
            let process = process.ok_or("missing process binding")?;
            if process.pid() != request.pid {
                return Err("session process changed; start a new binding".into());
            }
            let read_started = Instant::now();
            let calls_before = svm.calls();
            let mut buffers: Vec<Vec<u8>> =
                request.ranges.iter().map(|&(_, length)| vec![0; length]).collect();
            let mut reads: Vec<(u64, &mut [u8])> = request
                .ranges
                .iter()
                .zip(&mut buffers)
                .map(|(&(address, _), buffer)| (address, buffer.as_mut_slice()))
                .collect();
            svm.read_batch(process, &mut reads).map_err(|error| error.to_string())?;
            if Instant::now() >= deadline {
                return Err("total session deadline reached; sample discarded".into());
            }
            let elapsed_ms = read_started.elapsed().as_secs_f64() * 1000.0;
            let mut reply = json!({"id":request.id,"status":"complete",
                "data":buffers.concat().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                "round_trip_ms":elapsed_ms, "sample_calls":svm.calls() - calls_before});
            if first {
                reply["startup_ms"] = json!(initialization_ms);
                reply["discovery_ms"] = json!(discovery_ms);
                reply["discovery_calls"] = json!(discovery_calls);
            }
            previous_id = Some(request.id);
            Ok(reply)
        });
        match result {
            Ok(reply) => write_reply(&mut output, reply)?,
            Err(error) => {
                write_reply(&mut output, json!({"id":id,"status":"error","error":error}))?;
                return Ok(1);
            }
        }
    }
}

fn read_line(input: &mut impl BufRead) -> Result<Option<String>, String> {
    let mut bytes = Vec::new();
    input
        .take(MAX_LINE_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|error| format!("read session input: {error}"))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() as u64 > MAX_LINE_BYTES || bytes.last() != Some(&b'\n') {
        return Err("session request missing newline or over 4096 bytes".into());
    }
    String::from_utf8(bytes).map(Some).map_err(|_| "session input is not UTF-8".into())
}

fn decode_request(line: &str) -> Result<Request, String> {
    let request: Value =
        serde_json::from_str(line).map_err(|error| format!("request JSON: {error}"))?;
    let object = request.as_object().ok_or("request must be an object")?;
    let batch = object.contains_key("ranges");
    let fields: &[&str] =
        if batch { &["id", "pid", "ranges"] } else { &["id", "pid", "address", "length"] };
    if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("request requires id,pid and ranges or address,length".into());
    }
    let id = request["id"].as_u64().ok_or("id must be u64")?;
    let pid = request["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|&pid| pid != 0)
        .ok_or("pid must be a nonzero u32")?;
    let ranges = if batch {
        let values = request["ranges"].as_array().ok_or("ranges must be an array")?;
        if values.is_empty() || values.len() > MAX_RANGES {
            return Err("ranges must contain 1..8 entries".into());
        }
        values.iter().map(decode_range).collect::<Result<Vec<_>, _>>()?
    } else {
        vec![decode_range(&json!({"address":request["address"], "length":request["length"]}))?]
    };
    let length: usize = ranges.iter().map(|&(_, length)| length).sum();
    if length > MAX_DATA_BYTES {
        return Err("aggregate sample exceeds 4096 bytes".into());
    }
    Ok(Request { id, pid, ranges })
}

fn decode_range(value: &Value) -> Result<(u64, usize), String> {
    let object = value.as_object().ok_or("range must be an object")?;
    if object.len() != 2 || !object.contains_key("address") || !object.contains_key("length") {
        return Err("range requires exactly address,length".into());
    }
    let length = value["length"]
        .as_u64()
        .filter(|length| (1..=MAX_DATA_BYTES as u64).contains(length))
        .ok_or("length must be 1..4096")?;
    let address = value["address"]
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("address must be a 0x-prefixed hexadecimal string")?;
    let address = u64::from_str_radix(address, 16).map_err(|_| "address exceeds u64")?;
    if !is_canonical_48(address)
        || address.checked_add(length - 1).is_none_or(|last| !is_canonical_48(last))
    {
        return Err("virtual range must be nonwrapping and canonical".into());
    }
    Ok((address, length as usize))
}

fn write_reply(output: &mut impl Write, reply: Value) -> Result<(), String> {
    writeln!(output, "{reply}")
        .and_then(|()| output.flush())
        .map_err(|error| format!("session output: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_bounded_and_strictly_typed() {
        for line in [
            r#"{"id":1,"pid":42,"address":"0xaffc","length":0}"#,
            r#"{"id":1,"pid":42,"address":"0xaffc","length":4097}"#,
            r#"{"id":true,"pid":42,"address":"0xaffc","length":4}"#,
            r#"{"id":1,"pid":"42","address":"0xaffc","length":4}"#,
            r#"{"id":1,"pid":0,"address":"0xaffc","length":4}"#,
            r#"{"id":1,"pid":4294967296,"address":"0xaffc","length":4}"#,
            r#"{"id":1,"pid":42,"address":45052,"length":4}"#,
            r#"{"id":1,"pid":42,"address":"0xffffffffffffffff","length":4}"#,
            r#"{"id":1,"pid":42,"address":"0x800000000000","length":4}"#,
            r#"{"id":1,"pid":42,"address":"0xaffc","length":4,"retry":true}"#,
            "not-json",
        ] {
            assert!(decode_request(line).is_err(), "{line}");
        }
        assert_eq!(
            decode_request(r#"{"id":7,"pid":42,"address":"0xaffc","length":4}"#).unwrap(),
            Request { id: 7, pid: 42, ranges: vec![(0xaffc, 4)] }
        );
    }

    #[test]
    fn request_lines_require_newline_and_allow_clean_eof() {
        assert_eq!(read_line(&mut b"".as_slice()).unwrap(), None);
        assert_eq!(read_line(&mut b"{}\n".as_slice()).unwrap(), Some("{}\n".into()));
        for bytes in [b"{}".to_vec(), vec![b'x'; MAX_LINE_BYTES as usize + 1], vec![0xff, b'\n']] {
            assert!(read_line(&mut bytes.as_slice()).is_err());
        }
    }

    #[test]
    fn batch_ranges_preserve_order_and_enforce_aggregate_limit() {
        let request = decode_request(
            r#"{"id":1,"pid":42,"ranges":[{"address":"0x1000","length":2048},{"address":"0x9000","length":2048}]}"#,
        )
        .unwrap();
        assert_eq!(request.ranges, [(0x1000, 2048), (0x9000, 2048)]);
        for value in [
            json!({"id":2,"pid":42,"ranges":[]}),
            json!({"id":2,"pid":42,"ranges":vec![json!({"address":"0x1000","length":1});9]}),
            json!({"id":2,"pid":42,"ranges":[{"address":"0x1000","length":4096},{"address":"0x2000","length":1}]}),
            json!({"id":2,"pid":42,"ranges":[{"address":"0x1000","length":1,"unknown":0}]}),
        ] {
            assert!(decode_request(&value.to_string()).is_err());
        }
    }
}
