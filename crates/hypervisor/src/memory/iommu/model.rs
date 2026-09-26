use super::{AcpiHeader, Limit, ParseError, ParseErrorKind, error};

// Policy bounds, intentionally independent of advertised lengths/counts.
pub const MAX_UNITS: usize = 16;
pub const MAX_FORMS: usize = MAX_UNITS * 3;
pub const MAX_REQUESTER_SCOPES: usize = 256;
pub const MAX_SPECIAL_DEVICES: usize = 64;
pub const MAX_ACPI_DEVICES: usize = 64;
pub const MAX_UID_BYTES: usize = 64;
pub const MAX_MEMORY_REGIONS: usize = 64;
pub const MAX_MCFG_ALLOCATIONS: usize = 32;
pub const MAX_DIAGNOSTICS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Bounded<T: Copy, const N: usize> {
    pub data: [T; N],
    pub len: usize,
}

impl<T: Copy, const N: usize> Bounded<T, N> {
    pub const fn new(empty: T) -> Self {
        Self { data: [empty; N], len: 0 }
    }
    pub fn as_slice(&self) -> &[T] {
        &self.data[..self.len]
    }
    pub fn push(
        &mut self,
        value: T,
        table: [u8; 4],
        offset: usize,
        limit: Limit,
    ) -> Result<(), ParseError> {
        if self.len == N {
            return Err(error(table, offset, ParseErrorKind::LimitExceeded(limit)));
        }
        self.data[self.len] = value;
        self.len += 1;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovery {
    pub ivrs: Ivrs,
    pub mcfg: Mcfg,
    pub(super) complete: bool,
}

impl Discovery {
    pub const EMPTY: Self = Self { ivrs: Ivrs::EMPTY, mcfg: Mcfg::EMPTY, complete: false };
    /// Both tables parsed. This says nothing about hardware or authentication.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
    /// Invalidate the report in place; inaccessible backing slots are reused.
    pub fn clear(&mut self) {
        self.ivrs.clear();
        self.mcfg.clear();
        self.complete = false;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ivrs {
    pub header: AcpiHeader,
    pub iv_info: u32,
    pub(super) units: Bounded<IommuUnit, MAX_UNITS>,
    pub(super) forms: Bounded<IvhdForm, MAX_FORMS>,
    pub(super) scopes: Bounded<RequesterScope, MAX_REQUESTER_SCOPES>,
    pub(super) special: Bounded<SpecialDevice, MAX_SPECIAL_DEVICES>,
    pub(super) acpi: Bounded<AcpiDevice, MAX_ACPI_DEVICES>,
    pub(super) regions: Bounded<MemoryRegion, MAX_MEMORY_REGIONS>,
    pub(super) diagnostics: Bounded<Diagnostic, MAX_DIAGNOSTICS>,
}

impl Ivrs {
    pub const EMPTY: Self = Self {
        header: AcpiHeader::EMPTY,
        iv_info: 0,
        units: Bounded::new(IommuUnit::EMPTY),
        forms: Bounded::new(IvhdForm::EMPTY),
        scopes: Bounded::new(RequesterScope::EMPTY),
        special: Bounded::new(SpecialDevice::EMPTY),
        acpi: Bounded::new(AcpiDevice::EMPTY),
        regions: Bounded::new(MemoryRegion::EMPTY),
        diagnostics: Bounded::new(Diagnostic::EMPTY),
    };
    pub fn units(&self) -> &[IommuUnit] {
        self.units.as_slice()
    }
    pub fn forms(&self) -> &[IvhdForm] {
        self.forms.as_slice()
    }
    pub fn requester_scopes(&self) -> &[RequesterScope] {
        self.scopes.as_slice()
    }
    pub fn special_devices(&self) -> &[SpecialDevice] {
        self.special.as_slice()
    }
    pub fn acpi_devices(&self) -> &[AcpiDevice] {
        self.acpi.as_slice()
    }
    pub fn memory_regions(&self) -> &[MemoryRegion] {
        self.regions.as_slice()
    }
    pub fn diagnostics(&self) -> &[Diagnostic] {
        self.diagnostics.as_slice()
    }
    pub fn has_unresolved_diagnostics(&self) -> bool {
        self.diagnostics().iter().any(|diagnostic| diagnostic.kind.requires_resolution())
    }
    pub(super) fn clear(&mut self) {
        self.header = AcpiHeader::EMPTY;
        self.iv_info = 0;
        self.units.len = 0;
        self.forms.len = 0;
        self.scopes.len = 0;
        self.special.len = 0;
        self.acpi.len = 0;
        self.regions.len = 0;
        self.diagnostics.len = 0;
    }
    pub(super) fn diagnose(
        &mut self,
        kind: DiagnosticKind,
        offset: u32,
        related_offset: Option<u32>,
    ) -> Result<(), ParseError> {
        self.diagnostics.push(
            Diagnostic { kind, offset, related_offset },
            *b"IVRS",
            offset as usize,
            Limit::Diagnostics,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IommuUnit {
    pub segment: u16,
    pub device_id: u16,
    pub capability_offset: u16,
    pub mmio_base: u64,
    pub first_form_offset: u32,
    /// Bit 0 = 10h, bit 1 = 11h, bit 2 = 40h; no preferred form is selected.
    pub form_mask: u8,
}
impl IommuUnit {
    const EMPTY: Self = Self {
        segment: 0,
        device_id: 0,
        capability_offset: 0,
        mmio_base: 0,
        first_form_offset: 0,
        form_mask: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IvhdForm {
    pub unit_index: u16,
    pub offset: u32,
    pub kind: u8,
    pub flags: u8,
    pub iommu_info: u16,
    /// Raw legacy feature reporting for 10h, attributes for 11h/40h.
    pub feature_info: u32,
    pub efr: Option<u64>,
    pub efr2: Option<u64>,
}
impl IvhdForm {
    const EMPTY: Self = Self {
        unit_index: 0,
        offset: 0,
        kind: 0,
        flags: 0,
        iommu_info: 0,
        feature_info: 0,
        efr: None,
        efr2: None,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequesterRange {
    pub first: u16,
    pub last: u16,
}
impl RequesterRange {
    pub fn contains(self, device: u16) -> bool {
        self.first <= device && device <= self.last
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.first <= other.last && other.first <= self.last
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequesterKind {
    All,
    Select,
    Range,
    AliasSelect,
    AliasRange,
    ExtendedSelect,
    ExtendedRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequesterScope {
    pub form_index: u16,
    pub offset: u32,
    pub kind: RequesterKind,
    pub range: RequesterRange,
    pub dte_settings: u8,
    /// Transaction source shared by every actual peripheral in the range.
    pub alias_source: Option<u16>,
    pub extended_settings: Option<u32>,
}
impl RequesterScope {
    const EMPTY: Self = Self {
        form_index: 0,
        offset: 0,
        kind: RequesterKind::All,
        range: RequesterRange { first: 0, last: 0 },
        dte_settings: 0,
        alias_source: None,
        extended_settings: None,
    };
    pub(super) fn same_declaration(self, other: Self) -> bool {
        self.kind == other.kind
            && self.range == other.range
            && self.dte_settings == other.dte_settings
            && self.alias_source == other.alias_source
            && self.extended_settings == other.extended_settings
    }
    pub(super) fn source_range(self) -> RequesterRange {
        match self.alias_source {
            Some(source) => RequesterRange { first: source, last: source },
            None => self.range,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecialVariety {
    IoApic,
    Hpet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecialDevice {
    pub form_index: u16,
    pub offset: u32,
    pub source_id: u16,
    pub dte_settings: u8,
    pub handle: u8,
    pub variety: SpecialVariety,
}
impl SpecialDevice {
    const EMPTY: Self = Self {
        form_index: 0,
        offset: 0,
        source_id: 0,
        dte_settings: 0,
        handle: 0,
        variety: SpecialVariety::IoApic,
    };
    pub(super) fn same_declaration(self, other: Self) -> bool {
        self.source_id == other.source_id
            && self.dte_settings == other.dte_settings
            && self.handle == other.handle
            && self.variety == other.variety
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UidFormat {
    Absent,
    Integer,
    String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcpiDevice {
    pub form_index: u16,
    pub offset: u32,
    pub source_id: u16,
    pub dte_settings: u8,
    /// Preserve encoded ACPI integer/string IDs; do not guess a namespace match.
    pub hardware_id: [u8; 8],
    pub compatible_id: [u8; 8],
    pub uid_format: UidFormat,
    pub(super) uid_bytes: [u8; MAX_UID_BYTES],
    pub(super) uid_length: u8,
}
impl AcpiDevice {
    pub(super) const EMPTY: Self = Self {
        form_index: 0,
        offset: 0,
        source_id: 0,
        dte_settings: 0,
        hardware_id: [0; 8],
        compatible_id: [0; 8],
        uid_format: UidFormat::Absent,
        uid_bytes: [0; MAX_UID_BYTES],
        uid_length: 0,
    };
    pub fn uid(&self) -> &[u8] {
        &self.uid_bytes[..self.uid_length as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryScope {
    /// IVMD 20h applies to every device in the system (48882-3.11 p309).
    AllDevices,
    Devices {
        segment: u16,
        range: RequesterRange,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemorySemantics {
    /// IOMMU translation bypass/read-write exclusion, NOT denied DMA memory.
    /// IR/IW/Unity are ignored while exclusion is set (48882-3.11 pp54,309).
    Exclusion,
    Permissions {
        read: bool,
        write: bool,
        unity: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub offset: u32,
    /// Closest preceding IVHD, retained even for the global 20h scope.
    pub preceding_form_index: u16,
    pub scope: MemoryScope,
    pub raw_flags: u8,
    pub semantics: MemorySemantics,
    pub start: u64,
    /// Inclusive last byte; computed with checked arithmetic, never rounded.
    pub last: u64,
    pub length: u64,
}
impl MemoryRegion {
    const EMPTY: Self = Self {
        offset: 0,
        preceding_form_index: 0,
        scope: MemoryScope::AllDevices,
        raw_flags: 0,
        semantics: MemorySemantics::Exclusion,
        start: 0,
        last: 0,
        length: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticKind {
    /// Actual peripheral ranges intersect within one IVHD; no precedence chosen.
    RequesterOverlap,
    /// Declarations share a transaction source within one IOMMU but disagree
    /// on DTE settings. Both declarations remain available for resolution.
    SourceSettingsConflict,
    /// Conflicting assignment of a numeric requester to different IOMMUs.
    RequesterAcrossUnits,
    /// Two forms describe different numeric declarations; both are retained.
    FormRequesterScopesDiffer,
    FormSpecialDevicesDiffer,
    /// Raw properties differ. Legacy and extended encodings need not agree.
    FormPropertiesDiffer,
    /// Firmware metadata references a source not described by a numeric scope.
    AliasSourceUndeclared,
    /// Same ACPI instance declared twice; source/settings may also disagree.
    DuplicateAcpiIdentity,
    /// Valid ACPI instances may share an IOMMU-visible source (p307, note 5).
    SharedAcpiSource,
    /// ACPI source also occurs in a numeric declaration; not a namespace match.
    AcpiSourceAlsoNumeric,
    DuplicateSpecialIdentity,
    OverlappingMemoryRegions,
    /// Preserved form field contains reserved bits without an explicit MBZ rule.
    ReservedIvhdBits,
    /// Minimum 16-KiB IOMMU register aperture intersects supplied ECAM bytes.
    IommuMmioOverlapsEcam,
    /// A form's declared capability is unavailable through the supplied MCFG.
    IommuOutsideMcfg,
}

impl DiagnosticKind {
    /// Whether the observation leaves an unresolved structural question.
    /// Even a fully resolved inventory establishes no DMA ownership or trust.
    pub const fn requires_resolution(self) -> bool {
        // Multiple ACPI instances sharing a source are explicitly allowed by
        // 48882-3.11 p307 note 5; they remain visible informational evidence.
        !matches!(self, Self::SharedAcpiSource)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub kind: DiagnosticKind,
    pub offset: u32,
    pub related_offset: Option<u32>,
}
impl Diagnostic {
    const EMPTY: Self =
        Self { kind: DiagnosticKind::RequesterOverlap, offset: 0, related_offset: None };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McfgAllocation {
    pub offset: u32,
    /// Segment-relative bus-zero base, not rebased to `start_bus`.
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
    /// Address of the first admitted bus, checked against u64 overflow.
    pub start: u64,
    pub last: u64,
}
impl McfgAllocation {
    const EMPTY: Self =
        Self { offset: 0, base: 0, segment: 0, start_bus: 0, end_bus: 0, start: 0, last: 0 };
    /// Pure address calculation, not permission to access PCI configuration.
    pub fn address(&self, requester: u16, register: u16) -> Option<u64> {
        let bus = (requester >> 8) as u8;
        if bus < self.start_bus || bus > self.end_bus || register >= 4096 {
            return None;
        }
        self.base.checked_add((requester as u64) << 12)?.checked_add(register as u64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mcfg {
    pub header: AcpiHeader,
    pub(super) allocations: Bounded<McfgAllocation, MAX_MCFG_ALLOCATIONS>,
}
impl Mcfg {
    pub const EMPTY: Self =
        Self { header: AcpiHeader::EMPTY, allocations: Bounded::new(McfgAllocation::EMPTY) };
    pub fn allocations(&self) -> &[McfgAllocation] {
        self.allocations.as_slice()
    }
    pub(super) fn clear(&mut self) {
        self.header = AcpiHeader::EMPTY;
        self.allocations.len = 0;
    }
}
