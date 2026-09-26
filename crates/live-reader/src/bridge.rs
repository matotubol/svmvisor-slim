//! One bounded local batch session; no physical transactions occur in steady-state sampling.

use std::{
    fmt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use svmvisor_card_abi::batch::{
    self, BatchRange, BatchRequest, BindingEvidence, HEADER_BYTES, MAGIC, MAX_DATA_BYTES,
    MAX_RANGES, MAX_RESPONSE_BYTES, Operation, Status, VERSION,
};

use crate::transport::{Exchange, NativeTransport};

/// Why an exchange failed. Only a resident refusal of a well-formed request keeps the session.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The resident could not translate or read a requested range; the binding remains.
    Unreadable,
    /// The resident no longer accepts the bound process identity; the session remains.
    Unbound,
    /// Anything else. The session is poisoned and every later call fails without retrying.
    Fatal(String),
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Fatal(message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Self::Fatal(message.into())
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable => formatter.write_str("resident could not read the requested range"),
            Self::Unbound => formatter.write_str("resident no longer recognizes the process"),
            Self::Fatal(message) => formatter.write_str(message),
        }
    }
}

pub(crate) struct ReadBridge {
    transport: Box<dyn Exchange>,
    session: u64,
    boot: u64,
    calls: u64,
    sequence: u64,
    context_cpu: Option<u32>,
    context_exit_sequence: u64,
    max_calls: u64,
    deadline: Option<Instant>,
    phase_deadline: Option<Instant>,
    phase: &'static str,
    response_timeout: Duration,
    failed: bool,
}

impl ReadBridge {
    /// `deadline` bounds the whole session; `None` leaves only per-phase and response limits.
    pub(crate) fn start(
        cpu: u16,
        max_calls: u64,
        deadline: Option<Duration>,
        response_timeout: Duration,
    ) -> Result<Self, String> {
        let started = Instant::now();
        let transport = NativeTransport::new(cpu)?;
        let session = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos() as u64
            ^ u64::from(std::process::id()).rotate_left(32);
        let bridge = Self::with_transport(
            Box::new(transport),
            session.max(1),
            max_calls,
            deadline
                .map(|deadline| {
                    deadline
                        .checked_sub(started.elapsed())
                        .ok_or("session deadline reached during initialization")
                })
                .transpose()?,
            response_timeout,
        )?;
        Ok(bridge)
    }

    pub(crate) fn with_transport(
        transport: Box<dyn Exchange>,
        session: u64,
        max_calls: u64,
        duration: Option<Duration>,
        response_timeout: Duration,
    ) -> Result<Self, String> {
        let deadline = duration
            .map(|duration| Instant::now().checked_add(duration).ok_or("invalid deadline"))
            .transpose()?;
        let mut bridge = Self {
            transport,
            session,
            boot: 0,
            calls: 0,
            sequence: 0,
            context_cpu: None,
            context_exit_sequence: 0,
            max_calls,
            deadline,
            phase_deadline: deadline,
            phase: "hello",
            response_timeout,
            failed: false,
        };
        bridge
            .exchange(Operation::Hello, 0, &[], BindingEvidence::EMPTY)
            .map_err(|failure| failure.to_string())?;
        Ok(bridge)
    }

    pub(crate) fn calls(&self) -> u64 {
        self.calls
    }

    pub(crate) fn failed(&self) -> bool {
        self.failed
    }

    pub(crate) fn context(
        &mut self,
    ) -> Result<svmvisor_card_abi::context::ContextObservation, String> {
        if self.failed {
            return Err("local session already failed; no retry".into());
        }
        let result = self.context_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn context_inner(&mut self) -> Result<svmvisor_card_abi::context::ContextObservation, String> {
        self.finish_phase()?;
        if self.calls >= self.max_calls {
            return Err("request limit reached".into());
        }
        self.calls += 1;
        let deadline = self.response_deadline()?;
        let bytes = self.transport.context(self.session, deadline)?;
        self.finish_phase()?;
        if Instant::now() >= deadline {
            return Err("context response deadline reached; discarded".into());
        }
        let observation = svmvisor_card_abi::context::ContextObservation::decode(&bytes)
            .map_err(|error| format!("invalid context response: {error:?}"))?;
        // Firmware slot numbering is not Windows group0 CPU numbering. Affinity selects
        // the caller; retain and compare the returned slot only within this session.
        if observation.session != self.session
            || observation.boot != self.boot
            || observation.cpu_slot >= 32
            || observation.exit_sequence <= self.context_exit_sequence
            || self.context_cpu.is_some_and(|cpu| cpu != observation.cpu_slot)
        {
            return Err("context session, boot or CPU mismatch".into());
        }
        self.context_cpu = Some(observation.cpu_slot);
        self.context_exit_sequence = observation.exit_sequence;
        Ok(observation)
    }

    pub(crate) fn begin_phase(
        &mut self,
        phase: &'static str,
        duration: Duration,
    ) -> Result<(), String> {
        if self.failed {
            return Err("local session already failed; no retry".into());
        }
        self.phase = phase;
        let end = Instant::now().checked_add(duration).ok_or("invalid phase deadline")?;
        self.phase_deadline = Some(self.deadline.map_or(end, |deadline| end.min(deadline)));
        Ok(())
    }

    pub(crate) fn finish_phase(&self) -> Result<(), String> {
        if self.phase_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(format!("{} deadline reached; calls={}", self.phase, self.calls));
        }
        Ok(())
    }

    fn response_deadline(&self) -> Result<Instant, String> {
        let end =
            Instant::now().checked_add(self.response_timeout).ok_or("invalid response deadline")?;
        Ok(self.phase_deadline.map_or(end, |deadline| end.min(deadline)))
    }

    pub(crate) fn read(&mut self, gpa: u64, output: &mut [u8]) -> Result<(), String> {
        let range = BatchRange {
            address: gpa,
            length: u32::try_from(output.len()).map_err(|_| "physical range too large")?,
        };
        let (_, bytes) = self
            .exchange(Operation::Physical, 0, &[range], BindingEvidence::EMPTY)
            .map_err(|failure| failure.to_string())?;
        output.copy_from_slice(&bytes);
        Ok(())
    }

    pub(crate) fn bind(&mut self, evidence: BindingEvidence) -> Result<u64, String> {
        self.exchange(Operation::Bind, 0, &[], evidence)
            .map(|(token, _)| token)
            .map_err(|failure| failure.to_string())
    }

    pub(crate) fn sample(&mut self, token: u64, ranges: &[BatchRange]) -> Result<Vec<u8>, Failure> {
        self.exchange(Operation::Sample, token, ranges, BindingEvidence::EMPTY)
            .map(|(_, bytes)| bytes)
    }

    fn exchange(
        &mut self,
        operation: Operation,
        token: u64,
        ranges: &[BatchRange],
        binding: BindingEvidence,
    ) -> Result<(u64, Vec<u8>), Failure> {
        if self.failed {
            return Err("local session already failed; no retry".into());
        }
        let result = self.exchange_inner(operation, token, ranges, binding);
        if matches!(result, Err(Failure::Fatal(_))) {
            self.failed = true;
        }
        result
    }

    fn exchange_inner(
        &mut self,
        operation: Operation,
        token: u64,
        ranges: &[BatchRange],
        binding: BindingEvidence,
    ) -> Result<(u64, Vec<u8>), Failure> {
        self.finish_phase()?;
        if self.calls >= self.max_calls {
            return Err("batch request limit reached".into());
        }
        if ranges.len() > MAX_RANGES {
            return Err("at most eight ranges are supported".into());
        }
        let mut request = BatchRequest {
            operation,
            session: self.session,
            boot: self.boot,
            sequence: self.sequence.checked_add(1).ok_or("sequence exhausted")?,
            token,
            count: ranges.len(),
            ranges: [BatchRange::EMPTY; MAX_RANGES],
            binding,
        };
        request.ranges[..ranges.len()].copy_from_slice(ranges);
        let encoded = request.encode();
        BatchRequest::decode(&encoded)
            .map_err(|error| format!("invalid batch request: {error:?}"))?;
        self.calls += 1;
        self.sequence = request.sequence;
        let deadline = self.response_deadline()?;
        let bytes = self.transport.exchange(&encoded, deadline)?;
        self.finish_phase()?;
        if Instant::now() >= deadline {
            return Err("response deadline reached; discarded".into());
        }
        let (boot, token, data) = decode_response(&bytes, request)?;
        self.boot = boot;
        Ok((token, data))
    }
}

fn decode_response(bytes: &[u8], request: BatchRequest) -> Result<(u64, u64, Vec<u8>), Failure> {
    if !(HEADER_BYTES + 4..=MAX_RESPONSE_BYTES).contains(&bytes.len()) || bytes.len() % 4 != 0 {
        return Err("invalid response length".into());
    }
    let word = |offset: usize| {
        u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
    };
    let wide = |offset: usize| u64::from(word(offset)) | (u64::from(word(offset + 4)) << 32);
    if word(0) != MAGIC
        || word(4) != u32::from(VERSION) | ((request.operation as u32) << 16)
        || batch::crc32(&bytes[..bytes.len() - 4]) != word(bytes.len() - 4)
    {
        return Err("response framing or CRC mismatch".into());
    }
    let boot = wide(16);
    let token = wide(32);
    if wide(8) != request.session
        || wide(24) != request.sequence
        || boot == 0
        || (request.operation != Operation::Hello && boot != request.boot)
        || word(48) as usize != request.count
        || bytes[52..64].iter().any(|byte| *byte != 0)
    {
        return Err("response session, boot or sequence mismatch".into());
    }
    let length = word(44) as usize;
    if length > MAX_DATA_BYTES
        || bytes.len() != HEADER_BYTES + ((length + 3) & !3) + 4
        || bytes[HEADER_BYTES + length..bytes.len() - 4].iter().any(|byte| *byte != 0)
    {
        return Err("invalid response data length/padding".into());
    }
    // Only Sample refusals are recoverable: the resident keeps the session after a failed range,
    // and clears just the binding after an identity change.
    match word(40) {
        0 => {}
        status if status == Status::Read as u32 && request.operation == Operation::Sample => {
            return Err(Failure::Unreadable);
        }
        status if status == Status::Binding as u32 && request.operation == Operation::Sample => {
            return Err(Failure::Unbound);
        }
        status => {
            return Err(format!("resident batch refused (status={status}); session ended").into());
        }
    }
    let expected: usize =
        request.ranges[..request.count].iter().map(|range| range.length as usize).sum();
    if length != expected
        || (request.operation == Operation::Hello && token != 0)
        || (request.operation == Operation::Bind && token == 0)
        || (request.operation == Operation::Sample && token != request.token)
    {
        return Err("response token or data length mismatch".into());
    }
    Ok((boot, token, bytes[HEADER_BYTES..HEADER_BYTES + length].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{cell::RefCell, rc::Rc};
    use svmvisor_card_abi::batch::REQUEST_BYTES;

    struct ContextTransport {
        inner: FakeTransport,
        observation: Rc<RefCell<svmvisor_card_abi::context::ContextObservation>>,
        sequences: Rc<RefCell<Vec<u64>>>,
    }

    impl Exchange for ContextTransport {
        fn exchange(
            &mut self,
            bytes: &[u8; REQUEST_BYTES],
            deadline: Instant,
        ) -> Result<Vec<u8>, String> {
            self.sequences.borrow_mut().push(BatchRequest::decode(bytes).unwrap().sequence);
            self.inner.exchange(bytes, deadline)
        }

        fn context(&mut self, _: u64, _: Instant) -> Result<Vec<u8>, String> {
            Ok(self.observation.borrow().encode().to_vec())
        }
    }

    fn observation() -> svmvisor_card_abi::context::ContextObservation {
        svmvisor_card_abi::context::ContextObservation {
            session: 1,
            boot: 7,
            exit_sequence: 10,
            cr3: 0x2000,
            cr4: 1 << 5,
            efer: 0xd01,
            lstar: 0xffff_f800_0010_0000,
            physical_bits: 48,
            cpu_slot: 3,
            page1gb: true,
        }
    }

    #[test]
    fn context_accounting_does_not_change_batch_sequences() {
        let sequences = Rc::new(RefCell::new(Vec::new()));
        let mut bridge = ReadBridge::with_transport(
            Box::new(ContextTransport {
                inner: FakeTransport { calls: Rc::new(RefCell::new(Vec::new())), corrupt: None },
                observation: Rc::new(RefCell::new(observation())),
                sequences: sequences.clone(),
            }),
            1,
            3,
            Some(Duration::from_secs(5)),
            Duration::from_secs(1),
        )
        .unwrap();
        bridge.context().unwrap();
        bridge.read(0x1000, &mut [0; 8]).unwrap();
        assert_eq!(bridge.calls(), 3);
        assert_eq!(*sequences.borrow(), [1, 2]);
        assert!(bridge.read(0x1000, &mut [0; 8]).unwrap_err().contains("limit"));
    }

    #[test]
    fn context_checks_session_boot_cpu_and_freshness_and_poisoning() {
        for field in ["session", "boot", "cpu", "replay"] {
            let observed = Rc::new(RefCell::new(observation()));
            let mut bridge = ReadBridge::with_transport(
                Box::new(ContextTransport {
                    inner: FakeTransport {
                        calls: Rc::new(RefCell::new(Vec::new())),
                        corrupt: None,
                    },
                    observation: observed.clone(),
                    sequences: Rc::new(RefCell::new(Vec::new())),
                }),
                1,
                20,
                Some(Duration::from_secs(5)),
                Duration::from_secs(1),
            )
            .unwrap();
            bridge.context().unwrap();
            {
                let mut value = observed.borrow_mut();
                value.exit_sequence += 1;
                match field {
                    "session" => value.session += 1,
                    "boot" => value.boot += 1,
                    "cpu" => value.cpu_slot += 1,
                    _ => value.exit_sequence -= 1,
                }
            }
            assert!(bridge.context().is_err(), "{field}");
            assert!(bridge.context().unwrap_err().contains("no retry"));
            assert!(bridge.read(0x1000, &mut [0; 8]).unwrap_err().contains("no retry"));
        }
    }

    #[test]
    fn unsupported_context_ends_session_without_manual_fallback() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut bridge = ReadBridge::with_transport(
            Box::new(FakeTransport { calls: calls.clone(), corrupt: None }),
            1,
            20,
            Some(Duration::from_secs(5)),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(bridge.context().unwrap_err().contains("unsupported"));
        assert!(bridge.read(0x1000, &mut [0; 8]).unwrap_err().contains("no retry"));
        assert_eq!(*calls.borrow(), [Operation::Hello]);
    }

    struct FakeTransport {
        calls: Rc<RefCell<Vec<Operation>>>,
        corrupt: Option<Operation>,
    }

    impl Exchange for FakeTransport {
        fn exchange(&mut self, bytes: &[u8; REQUEST_BYTES], _: Instant) -> Result<Vec<u8>, String> {
            let request = BatchRequest::decode(bytes).unwrap();
            self.calls.borrow_mut().push(request.operation);
            let mut output = [0; MAX_RESPONSE_BYTES];
            let length: usize =
                request.ranges[..request.count].iter().map(|range| range.length as usize).sum();
            let count = batch::encode_response(
                request,
                7,
                if request.operation == Operation::Hello { 0 } else { 9 },
                Status::Success,
                &vec![0xa5; length],
                &mut output,
            )
            .unwrap();
            if self.corrupt == Some(request.operation) {
                if request.operation == Operation::Hello {
                    output[32] = 9;
                    let crc = batch::crc32(&output[..count - 4]);
                    output[count - 4..count].copy_from_slice(&crc.to_le_bytes());
                } else {
                    output[16] ^= 1;
                }
            }
            Ok(output[..count].to_vec())
        }
    }

    #[test]
    fn discovery_bind_and_samples_use_one_logical_request_each() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut bridge = ReadBridge::with_transport(
            Box::new(FakeTransport { calls: calls.clone(), corrupt: None }),
            1,
            20,
            Some(Duration::from_secs(5)),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut physical = [0; 4096];
        bridge.read(0x1000, &mut physical).unwrap();
        assert_eq!(physical, [0xa5; 4096]);
        let token = bridge.bind(BindingEvidence::EMPTY).unwrap();
        for _ in 0..2 {
            assert_eq!(
                bridge.sample(token, &[BatchRange { address: 0x1234, length: 32 }]).unwrap(),
                vec![0xa5; 32]
            );
        }
        assert_eq!(
            *calls.borrow(),
            [
                Operation::Hello,
                Operation::Physical,
                Operation::Bind,
                Operation::Sample,
                Operation::Sample
            ]
        );
    }

    #[test]
    fn corrupt_response_poisoning_preserves_output_and_never_retries() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut bridge = ReadBridge::with_transport(
            Box::new(FakeTransport { calls: calls.clone(), corrupt: Some(Operation::Physical) }),
            1,
            20,
            Some(Duration::from_secs(5)),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut bytes = [0x55; 32];
        assert!(bridge.read(0x1000, &mut bytes).is_err());
        assert_eq!(bytes, [0x55; 32]);
        assert!(bridge.read(0x1000, &mut bytes).unwrap_err().contains("no retry"));
        assert_eq!(calls.borrow().len(), 2);
    }

    #[test]
    fn hello_requires_zero_token_even_with_valid_crc() {
        let request = BatchRequest {
            operation: Operation::Hello,
            session: 11,
            boot: 0,
            sequence: 1,
            token: 0,
            count: 0,
            ranges: [BatchRange::EMPTY; MAX_RANGES],
            binding: BindingEvidence::EMPTY,
        };
        let mut output = [0; MAX_RESPONSE_BYTES];
        let length =
            batch::encode_response(request, 7, 0, Status::Success, &[], &mut output).unwrap();
        assert_eq!(decode_response(&output[..length], request).unwrap(), (7, 0, Vec::new()));
        for token in [1u64, 9, u64::MAX] {
            output[32..40].copy_from_slice(&token.to_le_bytes());
            let crc = batch::crc32(&output[..length - 4]);
            output[length - 4..length].copy_from_slice(&crc.to_le_bytes());
            assert_eq!(
                decode_response(&output[..length], request).unwrap_err(),
                Failure::Fatal("response token or data length mismatch".into())
            );
        }
    }

    #[test]
    fn malformed_hello_poisoning_prevents_reads_and_retry() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut bridge = ReadBridge {
            transport: Box::new(FakeTransport {
                calls: calls.clone(),
                corrupt: Some(Operation::Hello),
            }),
            session: 1,
            boot: 0,
            calls: 0,
            sequence: 0,
            context_cpu: None,
            context_exit_sequence: 0,
            max_calls: 20,
            deadline: Some(deadline),
            phase_deadline: Some(deadline),
            phase: "hello",
            response_timeout: Duration::from_secs(1),
            failed: false,
        };
        assert_eq!(
            bridge.exchange(Operation::Hello, 0, &[], BindingEvidence::EMPTY).unwrap_err(),
            Failure::Fatal("response token or data length mismatch".into())
        );
        assert!(bridge.failed);
        assert_eq!(bridge.boot, 0);
        let mut bytes = [0x55; 32];
        assert!(bridge.read(0x1000, &mut bytes).unwrap_err().contains("no retry"));
        assert_eq!(bytes, [0x55; 32]);
        assert!(
            bridge
                .exchange(Operation::Hello, 0, &[], BindingEvidence::EMPTY)
                .unwrap_err()
                .to_string()
                .contains("no retry")
        );
        assert_eq!(*calls.borrow(), [Operation::Hello]);
    }

    #[test]
    fn only_sample_read_and_binding_refusals_keep_the_session() {
        let mut request = BatchRequest {
            operation: Operation::Sample,
            session: 11,
            boot: 7,
            sequence: 3,
            token: 9,
            count: 1,
            ranges: [BatchRange::EMPTY; MAX_RANGES],
            binding: BindingEvidence::EMPTY,
        };
        request.ranges[0] = BatchRange { address: 0x1000, length: 3 };
        let refusal = |request: BatchRequest, status| {
            let mut output = [0; MAX_RESPONSE_BYTES];
            let length = batch::encode_response(request, 7, 9, status, &[], &mut output).unwrap();
            decode_response(&output[..length], request).unwrap_err()
        };
        assert_eq!(refusal(request, Status::Read), Failure::Unreadable);
        assert_eq!(refusal(request, Status::Binding), Failure::Unbound);
        for status in [Status::Identity, Status::Sequence, Status::Shape] {
            assert!(matches!(refusal(request, status), Failure::Fatal(_)), "{status:?}");
        }
        request.operation = Operation::Physical;
        assert!(matches!(refusal(request, Status::Read), Failure::Fatal(_)));
    }

    #[test]
    fn stale_identity_lengths_tokens_and_error_status_are_rejected_even_with_valid_crc() {
        let mut request = BatchRequest {
            operation: Operation::Sample,
            session: 11,
            boot: 7,
            sequence: 3,
            token: 9,
            count: 1,
            ranges: [BatchRange::EMPTY; MAX_RANGES],
            binding: BindingEvidence::EMPTY,
        };
        request.ranges[0] = BatchRange { address: 0x1000, length: 3 };
        let mut output = [0; MAX_RESPONSE_BYTES];
        let length =
            batch::encode_response(request, 7, 9, Status::Success, &[1, 2, 3], &mut output)
                .unwrap();
        assert_eq!(decode_response(&output[..length], request).unwrap().2, [1, 2, 3]);
        for offset in [8, 16, 24, 32, 40, 44, 48, 52, 67] {
            let mut corrupted = output[..length].to_vec();
            corrupted[offset] ^= 1;
            let crc = batch::crc32(&corrupted[..length - 4]);
            corrupted[length - 4..].copy_from_slice(&crc.to_le_bytes());
            assert!(decode_response(&corrupted, request).is_err(), "offset={offset}");
        }
        for truncated in [0, 32, 64, length - 1] {
            assert!(decode_response(&output[..truncated], request).is_err());
        }
    }
}
