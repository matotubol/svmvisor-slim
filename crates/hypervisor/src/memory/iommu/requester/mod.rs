//! Bounded resolution of declared numeric requesters in an immutable IVRS.
//!
//! This is an offline question about firmware declarations, not device identity,
//! active routing, DMA protection or permission to use a device/table/register.
//! Local success leaves all parser diagnostics and unrelated ambiguity intact.
//! See README.md for the deliberately conservative overlap/form rules.
//!
//! Sources: 48882-3.11 physical pp293-306 (text and layout PNGs checked), p307
//! (ACPI identity and shared sources). No form preference is inferred.
#![forbid(unsafe_code)]

mod interval;
mod numeric;
mod source;

use super::{
    AcpiDevice, Diagnostic, DiagnosticKind, Discovery, IommuUnit, IvhdForm, Ivrs, RequesterRange,
    RequesterScope, SpecialDevice,
};

pub use interval::{MAX_INTERVALS, RangeSummary, ResolutionInterval};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    pub segment: u16,
    /// Actual peripheral DeviceID, before the IVHD alias substitution.
    pub requester: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSettings {
    /// Raw Table 106 settings, preserved rather than converted into a policy.
    pub dte: u8,
    /// Raw Table 108 settings. None means no declaration supplied this field.
    pub extended: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceMapping {
    Identity,
    /// Every actual peripheral in the declaration uses this one source ID.
    Alias(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Form,
    Requester,
    Special,
    Acpi,
}

/// Index into the corresponding immutable Ivrs slice and its original offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub index: u16,
    pub form_index: u16,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceDeclaration<'a> {
    Requester(&'a RequesterScope),
    Special(&'a SpecialDevice),
    Acpi(&'a AcpiDevice),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceEvidence<'a> {
    pub location: Evidence,
    pub declaration: SourceDeclaration<'a>,
}

impl SourceEvidence<'_> {
    pub fn settings(self) -> SourceSettings {
        match self.declaration {
            SourceDeclaration::Requester(scope) => {
                SourceSettings { dte: scope.dte_settings, extended: scope.extended_settings }
            }
            SourceDeclaration::Special(device) => {
                SourceSettings { dte: device.dte_settings, extended: None }
            }
            SourceDeclaration::Acpi(device) => {
                SourceSettings { dte: device.dte_settings, extended: None }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    IncompleteDiscovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveErrorKind {
    EmptyInventory,
    InvalidRange,
    NoNumericDeclaration,
    /// A source ID alone cannot identify an IOAPIC, HPET or ACPI instance.
    AuxiliaryIdentityRequired,
    RequesterAcrossUnits,
    /// Exact repeated declarations are redundant; other overlaps are refused.
    OverlappingDeclarations,
    MissingFormDeclaration,
    FormDeclarationsDiffer,
    /// Reserved form fields or differing common form properties are unresolved.
    UnitDiagnostic(DiagnosticKind),
    AliasSourceUndeclared,
    AliasSourceNotDirect,
    SourceAcrossUnits,
    SourceSettingsConflict,
    SpecialIdentityConflict,
    SpecialFormsDiffer,
    /// Numeric/ACPI coexistence requires enumeration/namespace evidence.
    AcpiSourceRequiresIdentity,
}

/// A failure witness, not an exhaustive list of every problem in the inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolveError {
    pub query: Query,
    /// The original requester, or its source when validating an alias target.
    pub subject_requester: u16,
    pub kind: ResolveErrorKind,
    pub first: Option<Evidence>,
    pub second: Option<Evidence>,
}

/// Small immutable view. Construction neither resolves nor admits the inventory.
#[derive(Clone, Copy, Debug)]
pub struct Resolver<'a> {
    ivrs: &'a Ivrs,
}

impl<'a> Resolver<'a> {
    pub const fn new(ivrs: &'a Ivrs) -> Self {
        Self { ivrs }
    }

    pub fn from_discovery(discovery: &'a Discovery) -> Result<Self, InitError> {
        if !discovery.is_complete() {
            return Err(InitError::IncompleteDiscovery);
        }
        Ok(Self::new(&discovery.ivrs))
    }

    pub const fn inventory(&self) -> &'a Ivrs {
        self.ivrs
    }

    /// Original diagnostics, including ones outside this query's numeric scope.
    pub fn diagnostics(&self) -> &'a [Diagnostic] {
        self.ivrs.diagnostics()
    }

    pub fn resolve(&self, query: Query) -> Result<Resolution<'a>, ResolveError> {
        let declared = self.numeric(query, query.requester)?;
        self.check_unit(query, declared.unit_index)?;
        let source_id = declared.scope.alias_source.unwrap_or(query.requester);
        if declared.scope.alias_source.is_some() {
            self.check_alias_source(query, &declared, source_id)?;
        }
        let settings = self.check_source(query, &declared, source_id)?;
        Ok(Resolution {
            query,
            unit_index: declared.unit_index,
            source_id,
            settings,
            declaration: *declared.scope,
            ivrs: self.ivrs,
        })
    }

    fn unit_index(&self, form_index: u16) -> u16 {
        self.ivrs.forms()[usize::from(form_index)].unit_index
    }

    fn segment(&self, form_index: u16) -> u16 {
        self.ivrs.units()[usize::from(self.unit_index(form_index))].segment
    }

    fn form_evidence(&self, index: usize) -> Evidence {
        Evidence {
            kind: EvidenceKind::Form,
            index: index as u16,
            form_index: index as u16,
            offset: self.ivrs.forms()[index].offset,
        }
    }
}

/// Numeric evidence borrowing its full source inventory. It conveys no authority.
#[derive(Clone, Copy, Debug)]
pub struct Resolution<'a> {
    pub query: Query,
    pub unit_index: u16,
    pub source_id: u16,
    pub settings: SourceSettings,
    declaration: RequesterScope,
    ivrs: &'a Ivrs,
}

impl<'a> Resolution<'a> {
    pub fn unit(&self) -> &'a IommuUnit {
        &self.ivrs.units()[usize::from(self.unit_index)]
    }

    pub fn forms(&self) -> impl Iterator<Item = &'a IvhdForm> + '_ {
        self.ivrs.forms().iter().filter(|form| form.unit_index == self.unit_index)
    }

    /// Includes every equal declaration, even repeated entries in one form.
    pub fn requester_declarations(&self) -> impl Iterator<Item = &'a RequesterScope> + '_ {
        self.ivrs.requester_scopes().iter().filter(|scope| {
            self.ivrs.forms()[usize::from(scope.form_index)].unit_index == self.unit_index
                && scope.range.contains(self.query.requester)
        })
    }

    pub fn source_declarations(&self) -> impl Iterator<Item = SourceEvidence<'a>> + '_ {
        Resolver::new(self.ivrs).source_declarations(self.query.segment, self.source_id)
    }

    pub fn source_mapping(&self) -> SourceMapping {
        match self.declaration.alias_source {
            Some(source) => SourceMapping::Alias(source),
            None => SourceMapping::Identity,
        }
    }

    pub fn diagnostics(&self) -> &'a [Diagnostic] {
        self.ivrs.diagnostics()
    }
}

fn scope_evidence(index: usize, scope: &RequesterScope) -> Evidence {
    Evidence {
        kind: EvidenceKind::Requester,
        index: index as u16,
        form_index: scope.form_index,
        offset: scope.offset,
    }
}

fn failure(
    query: Query,
    subject_requester: u16,
    kind: ResolveErrorKind,
    first: Option<Evidence>,
    second: Option<Evidence>,
) -> ResolveError {
    ResolveError { query, subject_requester, kind, first, second }
}
