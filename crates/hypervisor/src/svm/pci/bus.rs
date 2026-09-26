use super::{BarAccess, Error, Function, Header, Interrupt, Region, Space, lane};
use crate::svm::configuration::{ConfigurationRoute, LegacySelector, ScalarTarget};

/// A complete synthetic segment-zero inventory for this route. Every missing
/// function is explicitly absent. Do not construct this policy from a partial
/// physical scan or use it to hide devices from the selected Windows contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusPolicy {
    pub route: ConfigurationRoute,
    pub memory: Region,
    pub io: Region,
}

/// A complete before/after configuration transition. Backend effects happen
/// before software state or guest RIP is committed. Bridge changes may affect
/// every descendant, and owners must account for those changes collectively.
#[derive(Clone, Copy, Debug)]
pub struct Transition<'a> {
    pub before: &'a Function,
    pub after: &'a Function,
}

/// Effect owner for the explicitly provided virtual fabric. No implementation
/// here claims physical ownership. A physical implementation would have to bind
/// fresh topology, DMA/interrupt policy, quiescence, lifetime and synchronization
/// before admitting the inventory; a test implementation cannot establish that.
///
/// `apply` must finish the full transition (including BME disable/drain and
/// interrupt re-routing) before returning success. Any owner error poisons the
/// bus: no later access may manufacture a successful guest continuation after a
/// possibly partial backend operation. DMA and MSI addresses are guest values.
pub trait ConfigOwner {
    fn admit(
        &mut self,
        policy: BusPolicy,
        denied: &[Region],
        functions: &[Function],
    ) -> Result<(), Error>;
    fn revalidate(&mut self) -> Result<(), Error>;
    fn apply(&mut self, transition: Transition<'_>) -> Result<(), Error>;
    fn dma(&mut self, bdf: u16, address: u64, bytes: u64, write: bool) -> Result<(), Error>;
    fn interrupt(&mut self, interrupt: Interrupt, asserted: bool) -> Result<(), Error>;
}

/// Default runtime choice. In particular, historical inventory and numerical
/// bank binding do not turn this into a hardware effects owner.
pub struct RefuseOwner;

impl ConfigOwner for RefuseOwner {
    fn admit(&mut self, _: BusPolicy, _: &[Region], _: &[Function]) -> Result<(), Error> {
        Err(Error::MissingOwner)
    }
    fn revalidate(&mut self) -> Result<(), Error> {
        Err(Error::MissingOwner)
    }
    fn apply(&mut self, _: Transition<'_>) -> Result<(), Error> {
        Err(Error::MissingOwner)
    }
    fn dma(&mut self, _: u16, _: u64, _: u64, _: bool) -> Result<(), Error> {
        Err(Error::MissingOwner)
    }
    fn interrupt(&mut self, _: Interrupt, _: bool) -> Result<(), Error> {
        Err(Error::MissingOwner)
    }
}

/// One exclusively borrowed fabric shared by both config transports. Native
/// integration must provide one synchronized instance for every participating
/// vCPU; one shadow selector per vCPU is not a substitute for that owner.
pub struct Bus<'a> {
    policy: BusPolicy,
    denied: &'a [Region],
    functions: &'a mut [Function],
    owner: &'a mut dyn ConfigOwner,
    selector: LegacySelector,
    poisoned: bool,
}

impl<'a> Bus<'a> {
    pub fn new(
        policy: BusPolicy,
        denied: &'a [Region],
        functions: &'a mut [Function],
        owner: &'a mut dyn ConfigOwner,
    ) -> Result<Self, Error> {
        let (ecam_base, ecam_bytes) = policy.route.aperture();
        if !policy.memory.valid()
            || policy.memory.base + policy.memory.bytes > 1 << 48
            || !policy.io.valid()
            || policy.io.base + policy.io.bytes > 1 << 16
            || policy.memory.overlaps(Region { base: ecam_base, bytes: ecam_bytes })
            || policy.io.overlaps(Region { base: 0xcf8, bytes: 8 })
            || denied.len() > 64
            || denied.iter().any(|r| !r.valid())
            || functions.len() > 64
        {
            return Err(Error::InvalidPolicy);
        }
        for (index, function) in functions.iter().enumerate() {
            let spec = function.spec();
            if u64::from(spec.bdf) >= ecam_bytes >> 12 {
                return Err(Error::OutsidePolicy);
            }
            if index > 0 && functions[index - 1].spec.bdf >= spec.bdf {
                return Err(Error::DuplicateFunction);
            }
            if let Some(parent) = spec.parent {
                let parent = functions[..index]
                    .iter()
                    .find(|f| f.spec.bdf == parent)
                    .ok_or(Error::InvalidTopology)?;
                let Header::Bridge(bridge) = parent.spec.header else {
                    return Err(Error::InvalidTopology);
                };
                if (spec.bdf >> 8) as u8 != bridge.secondary {
                    return Err(Error::InvalidTopology);
                }
                if let Header::Bridge(child) = spec.header {
                    if child.subordinate > bridge.subordinate {
                        return Err(Error::InvalidTopology);
                    }
                }
            } else if spec.bdf >> 8 != 0 {
                return Err(Error::InvalidTopology);
            }
            if spec.bdf & 7 != 0 {
                let zero = functions[..index]
                    .iter()
                    .find(|f| f.spec.bdf == spec.bdf & !7)
                    .ok_or(Error::InvalidTopology)?;
                if !zero.spec.multifunction || zero.spec.parent != spec.parent {
                    return Err(Error::InvalidTopology);
                }
            }
            for bar in spec.bars.iter().flatten() {
                let allowed = match bar.kind.space() {
                    Space::Memory => policy.memory,
                    Space::Io => policy.io,
                };
                if !allowed.contains(bar.allowed.base, bar.allowed.bytes)
                    || (bar.kind.space() == Space::Memory
                        && denied.iter().any(|r| r.overlaps(bar.allowed)))
                {
                    return Err(Error::OutsidePolicy);
                }
            }
            if let Header::Bridge(bridge) = spec.header {
                if u64::from(bridge.subordinate) >= ecam_bytes >> 20 {
                    return Err(Error::OutsidePolicy);
                }
                for (window, space) in [(bridge.memory, Space::Memory), (bridge.io, Space::Io)] {
                    if let Some(window) = window {
                        let allowed =
                            if space == Space::Memory { policy.memory } else { policy.io };
                        if !allowed.contains(window.base, window.bytes)
                            || (space == Space::Memory && denied.iter().any(|r| r.overlaps(window)))
                        {
                            return Err(Error::OutsidePolicy);
                        }
                    }
                }
                // Disjoint sibling bus intervals prevent ambiguous config routing.
                for other in &functions[..index] {
                    if other.spec.parent == spec.parent {
                        if let Header::Bridge(previous) = other.spec.header {
                            if bridge.secondary <= previous.subordinate
                                && previous.secondary <= bridge.subordinate
                            {
                                return Err(Error::InvalidTopology);
                            }
                        }
                    }
                }
            }
        }
        let bus = Self {
            policy,
            denied,
            functions,
            owner,
            selector: LegacySelector::admit(0).unwrap(),
            poisoned: false,
        };
        for (index, function) in bus.functions.iter().enumerate() {
            function.validate_active()?;
            bus.validate_overlap(index, function)?;
        }
        bus.owner.admit(policy, denied, bus.functions)?;
        Ok(bus)
    }

    pub const fn route(&self) -> ConfigurationRoute {
        self.policy.route
    }
    pub const fn poisoned(&self) -> bool {
        self.poisoned
    }

    fn validate_owner(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::MissingOwner);
        }
        let result = self.owner.revalidate();
        self.poisoned |= result.is_err();
        result
    }

    /// Shared CF8 shadow; no physical IN/OUT is issued, including disabled
    /// selector data accesses and CF9 reset. PPR physical pp40-42.
    pub fn io(&mut self, port: u16, width: u8, write: Option<u32>) -> Result<u32, Error> {
        if port == 0xcf8 && width == 4 {
            let selected = write.map(LegacySelector::admit).transpose().map_err(Error::Scalar)?;
            self.validate_owner()?;
            if let Some(selector) = selected {
                self.selector = selector;
            }
            return Ok(self.selector.raw());
        }
        let target = self.selector.data(port, width).map_err(Error::Scalar)?;
        self.access(target, write)
    }

    pub fn ecam(&mut self, address: u64, width: u8, write: Option<u32>) -> Result<u32, Error> {
        let target = self.policy.route.ecam_scalar(address, width).map_err(Error::Scalar)?;
        self.access(target, write)
    }

    pub fn access(&mut self, target: ScalarTarget, write: Option<u32>) -> Result<u32, Error> {
        let (register, shift, bits) = lane(target.register, target.width)?;
        if u64::from(target.bdf) >= self.policy.route.aperture().1 >> 12 {
            return Err(Error::OutsidePolicy);
        }
        self.validate_owner()?;
        let Some(index) = self.index(target.bdf).filter(|&i| self.visible(i)) else {
            return Ok(if write.is_some() { 0 } else { bits });
        };
        if let Some(value) = write {
            let mut next = self.functions[index];
            next.write_word(register, (value & bits) << shift, bits << shift)?;
            next.validate_active()?;
            self.validate_overlap(index, &next)?;
            if next != self.functions[index] {
                let result =
                    self.owner.apply(Transition { before: &self.functions[index], after: &next });
                self.poisoned |= result.is_err();
                result?;
                self.functions[index] = next;
            }
            Ok(0)
        } else {
            Ok(self.functions[index].read_word(register) >> shift & bits)
        }
    }

    /// Resolve a CPU device access after command and upstream bridge-window
    /// gates. This returns a device offset, never a host address.
    pub fn decode(&mut self, space: Space, address: u64, bytes: u64) -> Result<BarAccess, Error> {
        self.validate_owner()?;
        let mut found = None;
        for (index, function) in self.functions.iter().enumerate() {
            if !self.visible(index)
                || !function.enabled(space)
                || !self.path_window(index, space, address, bytes)
            {
                continue;
            }
            for slot in 0..6 {
                if let Some((bar_space, region)) = function.bar_region(slot) {
                    if space == bar_space && region.contains(address, bytes) {
                        if found.is_some() {
                            return Err(Error::Overlap);
                        }
                        found = Some(BarAccess {
                            bdf: function.spec.bdf,
                            bar: slot as u8,
                            offset: address - region.base,
                            bytes,
                        });
                    }
                }
            }
        }
        found.ok_or(Error::NoDecode)
    }

    /// Enforce BME at the requester and every upstream bridge before entering
    /// the admitted DMA owner. The owner composes the complete guest DVA span;
    /// a config BME bit never grants identity DMA or protected-memory access.
    pub fn dma(&mut self, bdf: u16, address: u64, bytes: u64, write: bool) -> Result<(), Error> {
        self.validate_owner()?;
        if bytes == 0 || address.checked_add(bytes).is_none() {
            return Err(Error::InvalidAccess);
        }
        let index = self.index(bdf).filter(|&i| self.visible(i)).ok_or(Error::OutsidePolicy)?;
        if !self.path_bus_master(index) {
            return Err(Error::BusMasterDisabled);
        }
        let result = self.owner.dma(bdf, address, bytes, write);
        self.poisoned |= result.is_err();
        result
    }

    /// An asserted MSI is emitted only when BME is enabled throughout its path.
    /// INTx assertion/deassertion goes through the same interrupt owner. The
    /// Interrupt Line byte is software routing metadata, not a physical vector.
    pub fn interrupt(&mut self, bdf: u16, asserted: bool) -> Result<(), Error> {
        self.validate_owner()?;
        let index = self.index(bdf).filter(|&i| self.visible(i)).ok_or(Error::OutsidePolicy)?;
        let function = &self.functions[index];
        let message = if function.msi.enabled {
            if !asserted {
                return Ok(());
            }
            if !self.path_bus_master(index) {
                return Err(Error::BusMasterDisabled);
            }
            Interrupt::Msi { bdf, address: function.msi.address, data: function.msi.data }
        } else {
            if function.spec.interrupt_pin == 0 {
                return Err(Error::NoInterrupt);
            }
            if asserted && function.command & (1 << 10) != 0 {
                return Err(Error::InterruptDisabled);
            }
            Interrupt::Intx { bdf, pin: function.spec.interrupt_pin, line: function.interrupt_line }
        };
        let result = self.owner.interrupt(message, asserted);
        self.poisoned |= result.is_err();
        result?;
        if !self.functions[index].msi.enabled {
            self.functions[index].intx_asserted = asserted;
        }
        Ok(())
    }

    /// The emulated device reports only the six defined RW1C status bits.
    /// This is an input from that device owner, never a guest memory access.
    pub fn report_status(&mut self, bdf: u16, status: u16) -> Result<(), Error> {
        self.validate_owner()?;
        if status & !0xf900 != 0 {
            return Err(Error::UnsupportedControl);
        }
        let index = self.index(bdf).ok_or(Error::OutsidePolicy)?;
        self.functions[index].status |= status;
        Ok(())
    }

    fn index(&self, bdf: u16) -> Option<usize> {
        self.functions.binary_search_by_key(&bdf, |f| f.spec.bdf).ok()
    }

    fn visible(&self, index: usize) -> bool {
        let bus = (self.functions[index].spec.bdf >> 8) as u8;
        let mut parent = self.functions[index].spec.parent;
        while let Some(bdf) = parent {
            let Some(index) = self.index(bdf) else { return false };
            let function = &self.functions[index];
            let Header::Bridge(bridge) = function.spec.header else { return false };
            if bus < bridge.secondary || bus > function.subordinate {
                return false;
            }
            parent = function.spec.parent;
        }
        true
    }

    fn path_bus_master(&self, mut index: usize) -> bool {
        loop {
            let function = &self.functions[index];
            if function.command & 4 == 0 {
                return false;
            }
            let Some(parent) = function.spec.parent else { return true };
            let Some(next) = self.index(parent) else { return false };
            index = next;
        }
    }

    fn path_window(&self, index: usize, space: Space, address: u64, bytes: u64) -> bool {
        let mut parent = self.functions[index].spec.parent;
        while let Some(bdf) = parent {
            let Some(index) = self.index(bdf) else { return false };
            let function = &self.functions[index];
            if !function.enabled(space)
                || function.bridge_window(space).is_none_or(|r| !r.contains(address, bytes))
            {
                return false;
            }
            parent = function.spec.parent;
        }
        true
    }

    fn validate_overlap(&self, changed: usize, next: &Function) -> Result<(), Error> {
        for slot in 0..6 {
            let Some((space, region)) = next.bar_region(slot) else { continue };
            if !next.enabled(space) {
                continue;
            }
            if space == Space::Memory && self.denied.iter().any(|r| r.overlaps(region)) {
                return Err(Error::OutsidePolicy);
            }
            for (index, function) in self.functions.iter().enumerate() {
                let function = if index == changed { next } else { function };
                if !function.enabled(space) {
                    continue;
                }
                for other in 0..6 {
                    if index == changed && other == slot {
                        continue;
                    }
                    if let Some((other_space, other_region)) = function.bar_region(other) {
                        if space == other_space && region.overlaps(other_region) {
                            return Err(Error::Overlap);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
