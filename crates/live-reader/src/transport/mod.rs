//! Local VMMCALL transport. Never probe an unconfirmed or legacy runtime.

use std::time::Instant;

use svmvisor_card_abi::{batch::REQUEST_BYTES, local};
use svmvisor_hypervisor::reader::batch::MAX_SERVICE_STEPS;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) use self::windows::NativeTransport;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows;

pub(crate) trait Exchange {
    fn exchange(
        &mut self,
        request: &[u8; REQUEST_BYTES],
        deadline: Instant,
    ) -> Result<Vec<u8>, String>;

    fn context(&mut self, _: u64, _: Instant) -> Result<Vec<u8>, String> {
        Err("automatic context is unsupported by this transport/runtime".into())
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
