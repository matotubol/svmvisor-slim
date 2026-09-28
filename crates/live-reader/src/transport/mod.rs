//! Local VMMCALL transport. Never probe an unconfirmed or legacy runtime.

use std::time::Instant;

use svmvisor_card_abi::{batch::REQUEST_BYTES, local};
use svmvisor_hypervisor::reader::batch::MAX_SERVICE_STEPS;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) use self::windows::NativeTransport;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows;

pub(crate) trait Exchange {
    /// Actual transport instructions issued, when this backend records them.
    /// Logical requests can need several SUBMIT/STEP calls.
    fn hypercalls(&self) -> Option<u64> {
        None
    }

    fn exchange(
        &mut self,
        request: &[u8; REQUEST_BYTES],
        deadline: Instant,
    ) -> Result<Vec<u8>, String>;

    fn context(&mut self, _: u64, _: Instant) -> Result<Vec<u8>, String> {
        Err("automatic context is unsupported by this transport/runtime".into())
    }

    /// Optional features are queried lazily; older transports support none.
    fn capabilities(&mut self, _: u64, _: Instant) -> Result<u64, String> {
        Ok(0)
    }
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub(crate) struct NativeTransport;

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
impl NativeTransport {
    pub(crate) fn new(_: u16) -> Result<Self, String> {
        Err("local VMMCALL requires native x64 Windows".into())
    }
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
impl Exchange for NativeTransport {
    fn exchange(&mut self, _: &[u8; REQUEST_BYTES], _: Instant) -> Result<Vec<u8>, String> {
        Err("local VMMCALL requires native x64 Windows".into())
    }
}

fn complete(deadline: Instant, mut call: impl FnMut(u64) -> (u64, u64)) -> Result<usize, String> {
    let mut operation = local::SUBMIT;
    for _ in 0..MAX_SERVICE_STEPS + 2 {
        if Instant::now() >= deadline {
            call(local::ABORT);
            return Err("local batch deadline reached; session aborted".into());
        }
        let (status, length) = call(operation);
        if Instant::now() >= deadline {
            call(local::ABORT);
            return Err("local batch response deadline reached; result discarded".into());
        }
        match status {
            local::COMPLETE => {
                return usize::try_from(length).map_err(|_| "invalid response length".into());
            }
            local::PENDING => operation = local::STEP,
            _ => {
                call(local::ABORT);
                return Err(format!("local VMMCALL refused (status={status}); session ended"));
            }
        }
    }
    call(local::ABORT);
    Err("local batch exceeded bounded continuation count; session aborted".into())
}

fn capabilities_complete(
    deadline: Instant,
    mut call: impl FnMut(u64) -> (u64, u64),
) -> Result<u64, String> {
    if Instant::now() >= deadline {
        return Err("capabilities deadline reached".into());
    }
    let (status, flags) = call(local::CAPABILITIES);
    if Instant::now() >= deadline {
        return Err("capabilities response deadline reached; discarded".into());
    }
    match (status, flags) {
        (local::COMPLETE, flags) => Ok(flags),
        // Version-one runtimes return exactly INVALID/0 for an unknown control operation.
        (local::INVALID, 0) => Ok(0),
        _ => Err(format!("invalid capabilities response (status={status})")),
    }
}

fn context_complete(
    deadline: Instant,
    mut call: impl FnMut(u64) -> (u64, u64),
) -> Result<(), String> {
    if Instant::now() >= deadline {
        return Err("context deadline reached".into());
    }
    let (status, length) = call(local::CONTEXT);
    if Instant::now() >= deadline {
        return Err("context response deadline reached; discarded".into());
    }
    if status != local::COMPLETE {
        return Err(format!(
            "automatic context unavailable or unsupported (status={status}); no retry"
        ));
    }
    if length != svmvisor_card_abi::context::RESPONSE_BYTES as u64 {
        return Err("invalid context response length".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    #[test]
    fn capabilities_accept_only_success_or_exact_legacy_refusal_without_retry() {
        for (reply, expected) in [
            ((local::COMPLETE, local::CAP_DIAGNOSTIC), Some(local::CAP_DIAGNOSTIC)),
            ((local::COMPLETE, 1 << 63), Some(1 << 63)),
            ((local::INVALID, 0), Some(0)),
            ((local::INVALID, 1), None),
            ((local::OWNER, 0), None),
            ((local::PENDING, 0), None),
            ((local::BUSY, 0), None),
        ] {
            let mut operations = Vec::new();
            let result = capabilities_complete(Instant::now() + Duration::from_secs(1), |op| {
                operations.push(op);
                reply
            });
            assert_eq!(result.ok(), expected);
            assert_eq!(operations, [local::CAPABILITIES]);
        }
        assert!(capabilities_complete(Instant::now(), |_| panic!("expired query")).is_err());
    }

    #[test]
    fn pending_work_continues_without_resubmitting_request() {
        let mut operations = Vec::new();
        let result = complete(Instant::now() + Duration::from_secs(1), |operation| {
            operations.push(operation);
            if operations.len() < 3 { (local::PENDING, 0) } else { (local::COMPLETE, 100) }
        })
        .unwrap();
        assert_eq!(result, 100);
        assert_eq!(operations, [local::SUBMIT, local::STEP, local::STEP]);
    }

    #[test]
    fn grouped_reader_finishes_four_kib_with_one_submit_and_three_steps() {
        use svmvisor_card_abi::batch::{
            BatchRange, BatchRequest, BindingEvidence, MAX_RANGES, Operation, Status,
        };
        use svmvisor_hypervisor::reader::{batch::BatchEngine, paging::PagingConfig};

        let config = PagingConfig::new(48, true, true).unwrap();
        let mut engine = BatchEngine::new();
        let mut request = BatchRequest {
            operation: Operation::Hello,
            session: 1,
            boot: 0,
            sequence: 1,
            token: 0,
            count: 0,
            ranges: [BatchRange::EMPTY; MAX_RANGES],
            binding: BindingEvidence::EMPTY,
        };
        engine.begin(request, 7, config).unwrap();
        engine.reset_response();
        request.operation = Operation::Physical;
        request.boot = 7;
        request.sequence = 2;
        request.count = 1;
        request.ranges[0] = BatchRange { address: 0x8000, length: 4096 };
        let mut operations = Vec::new();
        let length = complete(Instant::now() + Duration::from_secs(1), |operation| {
            operations.push(operation);
            if operation == local::SUBMIT {
                engine.begin(request, 7, config).unwrap();
            } else {
                assert_eq!(operation, local::STEP);
            }
            engine.advance_bounded(&mut |address, bytes| {
                for (offset, byte) in bytes.iter_mut().enumerate() {
                    *byte = (address + offset as u64) as u8;
                }
                Ok(())
            });
            match engine.response() {
                Some(response) => (local::COMPLETE, response.len() as u64),
                None => (local::PENDING, 0),
            }
        })
        .unwrap();
        assert_eq!(operations, [local::SUBMIT, local::STEP, local::STEP, local::STEP]);
        assert_eq!(length, 4164);
        let response = engine.response().unwrap();
        assert_eq!(
            u32::from_le_bytes(response[40..44].try_into().unwrap()),
            Status::Success as u32
        );
        assert!(response[64..4160].iter().enumerate().all(|(offset, byte)| *byte == offset as u8));
    }

    #[test]
    fn refusal_or_expired_deadline_aborts_without_retry() {
        for expired in [true, false] {
            let mut operations = Vec::new();
            let deadline =
                if expired { Instant::now() } else { Instant::now() + Duration::from_secs(1) };
            assert!(
                complete(deadline, |operation| {
                    operations.push(operation);
                    (local::OWNER, 0)
                })
                .is_err()
            );
            assert_eq!(operations.last(), Some(&local::ABORT));
            assert_eq!(
                operations.iter().filter(|&&op| op == local::SUBMIT).count(),
                usize::from(!expired)
            );
        }
    }
    #[test]
    fn endless_pending_is_aborted_at_the_engine_step_bound() {
        let mut operations = Vec::new();
        let result = complete(Instant::now() + Duration::from_secs(1), |operation| {
            operations.push(operation);
            (local::PENDING, 0)
        });
        assert!(result.unwrap_err().contains("continuation count"));
        assert_eq!(operations.len(), MAX_SERVICE_STEPS + 3);
        assert_eq!(operations.last(), Some(&local::ABORT));
    }

    #[test]
    fn optional_context_never_retries_or_accepts_wrong_length() {
        for (status, length) in [(local::INVALID, 0), (local::PENDING, 0), (local::COMPLETE, 79)] {
            let mut operations = Vec::new();
            assert!(
                context_complete(Instant::now() + Duration::from_secs(1), |operation| {
                    operations.push(operation);
                    (status, length)
                })
                .is_err()
            );
            assert_eq!(operations, [local::CONTEXT]);
        }
        assert!(
            context_complete(Instant::now() + Duration::from_secs(1), |_| (local::COMPLETE, 80))
                .is_ok()
        );
        assert!(
            context_complete(Instant::now(), |_| panic!("expired context must not call transport"))
                .is_err()
        );
    }
}
