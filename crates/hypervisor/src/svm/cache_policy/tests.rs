use super::*;
use core::sync::atomic::Ordering;

#[test]
fn sequential_service_reentry_cannot_join_between_generation_and_idle_publication() {
    for observe_idle in [false, true] {
        let shared = SharedCache::new();
        // This CPU joined the old generation and has reached departure.
        shared.phase.store(4, Ordering::Release);
        assert_eq!(shared.try_join(0), Some(Some(0)));
        shared.parked.fetch_or(2, Ordering::AcqRel);
        shared.departed.store(3, Ordering::Release);

        // Suspend the actual finisher's serialized publication between its
        // generation increment and phase=0. The old service can observe the
        // generation change and return; its next call must not enroll here.
        let finisher = shared.state.try_lock().unwrap();
        shared.generation.fetch_add(1, Ordering::AcqRel);
        assert_eq!(shared.phase.load(Ordering::Acquire), 4);
        assert_eq!(shared.try_join(0), None);
        assert_eq!(shared.parked.load(Ordering::Acquire), 3);
        shared.phase.store(0, Ordering::Release);
        assert_eq!(shared.try_join(0), None);
        drop(finisher);

        if observe_idle {
            assert_eq!(shared.try_join(0), Some(None));
        }
        // The next writer clears the masks before publishing work. Joining
        // cannot lose its bit to this reset, even if the idle interval was missed.
        let writer = shared.state.try_lock().unwrap();
        shared.parked.store(0, Ordering::Relaxed);
        shared.departed.store(0, Ordering::Relaxed);
        shared.phase.store(1, Ordering::Release);
        assert_eq!(shared.try_join(0), None);
        assert_eq!(shared.parked.load(Ordering::Acquire), 0);
        drop(writer);
        assert_eq!(shared.try_join(0), Some(Some(1)));
        assert_eq!(shared.parked.load(Ordering::Acquire), 1);
        assert_eq!(shared.try_join(1), Some(Some(1)));
        assert_eq!(shared.parked.load(Ordering::Acquire), 3);
    }
}
