//! Test-only bounded driver for the in-memory batch engine. These are not wire opcodes.

use std::time::Instant;

use svmvisor_hypervisor::reader::batch::MAX_SERVICE_STEPS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Work {
    Submit,
    Step,
    Abort,
}

pub(crate) enum Reply {
    Complete(usize),
    Pending,
    Refused,
}

pub(crate) fn complete(
    deadline: Instant,
    mut call: impl FnMut(Work) -> Reply,
) -> Result<usize, String> {
    let mut operation = Work::Submit;
    let mut submitted = false;
    for _ in 0..MAX_SERVICE_STEPS + 2 {
        if Instant::now() >= deadline {
            if submitted {
                call(Work::Abort);
            }
            return Err("batch deadline reached".into());
        }
        submitted = true;
        let reply = call(operation);
        if Instant::now() >= deadline {
            call(Work::Abort);
            return Err("batch response deadline reached; result discarded".into());
        }
        match reply {
            Reply::Complete(length) => return Ok(length),
            Reply::Pending => operation = Work::Step,
            Reply::Refused => {
                call(Work::Abort);
                return Err("batch refused; session ended".into());
            }
        }
    }
    call(Work::Abort);
    Err("batch exceeded bounded continuation count; session aborted".into())
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
            if operations.len() < 3 { Reply::Pending } else { Reply::Complete(100) }
        })
        .unwrap();
        assert_eq!(result, 100);
        assert_eq!(operations, [Work::Submit, Work::Step, Work::Step]);
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
            root_pa: 0,
            paging: 0,
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
            if operation == Work::Submit {
                engine.begin(request, 7, config).unwrap();
            } else {
                assert_eq!(operation, Work::Step);
            }
            engine.advance_bounded(&mut |address, bytes| {
                for (offset, byte) in bytes.iter_mut().enumerate() {
                    *byte = (address + offset as u64) as u8;
                }
                Ok(())
            });
            match engine.response() {
                Some(response) => Reply::Complete(response.len()),
                None => Reply::Pending,
            }
        })
        .unwrap();
        assert_eq!(operations, [Work::Submit, Work::Step, Work::Step, Work::Step]);
        assert_eq!(length, 4164);
        let response = engine.response().unwrap();
        assert_eq!(
            u32::from_le_bytes(response[40..44].try_into().unwrap()),
            Status::Success as u32
        );
        assert!(response[64..4160].iter().enumerate().all(|(offset, byte)| *byte == offset as u8));
    }

    #[test]
    fn preexpired_deadline_never_submits_or_cancels() {
        assert!(complete(Instant::now(), |_| panic!("nothing was submitted")).is_err());
    }

    #[test]
    fn refusal_cancels_once_without_retry() {
        let mut operations = Vec::new();
        assert!(
            complete(Instant::now() + Duration::from_secs(1), |operation| {
                operations.push(operation);
                Reply::Refused
            })
            .is_err()
        );
        assert_eq!(operations, [Work::Submit, Work::Abort]);
    }

    #[test]
    fn endless_pending_is_aborted_at_the_engine_step_bound() {
        let mut operations = Vec::new();
        let result = complete(Instant::now() + Duration::from_secs(1), |operation| {
            operations.push(operation);
            Reply::Pending
        });
        assert!(result.unwrap_err().contains("continuation count"));
        assert_eq!(operations.len(), MAX_SERVICE_STEPS + 3);
        assert_eq!(operations.last(), Some(&Work::Abort));
    }
}
