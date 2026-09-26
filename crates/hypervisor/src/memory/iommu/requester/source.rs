use super::numeric::Numeric;
use super::*;

impl<'a> Resolver<'a> {
    pub(super) fn source_declarations(
        &self,
        segment: u16,
        source: u16,
    ) -> impl Iterator<Item = SourceEvidence<'a>> + use<'a> {
        let ivrs = self.ivrs;
        let same_segment = move |form: u16| {
            let unit = ivrs.forms()[usize::from(form)].unit_index;
            ivrs.units()[usize::from(unit)].segment == segment
        };
        let numeric =
            ivrs.requester_scopes().iter().enumerate().filter_map(move |(index, scope)| {
                (same_segment(scope.form_index) && scope.source_range().contains(source)).then_some(
                    SourceEvidence {
                        location: scope_evidence(index, scope),
                        declaration: SourceDeclaration::Requester(scope),
                    },
                )
            });
        let special =
            ivrs.special_devices().iter().enumerate().filter_map(move |(index, device)| {
                (same_segment(device.form_index) && device.source_id == source).then_some(
                    SourceEvidence {
                        location: Evidence {
                            kind: EvidenceKind::Special,
                            index: index as u16,
                            form_index: device.form_index,
                            offset: device.offset,
                        },
                        declaration: SourceDeclaration::Special(device),
                    },
                )
            });
        let acpi = ivrs.acpi_devices().iter().enumerate().filter_map(move |(index, device)| {
            (same_segment(device.form_index) && device.source_id == source).then_some(
                SourceEvidence {
                    location: Evidence {
                        kind: EvidenceKind::Acpi,
                        index: index as u16,
                        form_index: device.form_index,
                        offset: device.offset,
                    },
                    declaration: SourceDeclaration::Acpi(device),
                },
            )
        });
        numeric.chain(special).chain(acpi)
    }

    pub(super) fn check_source(
        &self,
        query: Query,
        declared: &Numeric<'_>,
        source: u16,
    ) -> Result<SourceSettings, ResolveError> {
        // Unit collisions take precedence over shared-source setting failures.
        for entry in self.source_declarations(query.segment, source) {
            if self.unit_index(entry.location.form_index) != declared.unit_index {
                return Err(failure(
                    query,
                    source,
                    ResolveErrorKind::SourceAcrossUnits,
                    Some(declared.evidence),
                    Some(entry.location),
                ));
            }
        }
        let mut settings = SourceSettings {
            dte: declared.scope.dte_settings,
            extended: declared.scope.extended_settings,
        };
        let mut extended_evidence = declared.evidence;
        for entry in self.source_declarations(query.segment, source) {
            let other = entry.settings();
            let witness = if settings.dte != other.dte {
                Some(declared.evidence)
            } else if matches!((settings.extended, other.extended), (Some(a), Some(b)) if a != b) {
                Some(extended_evidence)
            } else {
                None
            };
            if let Some(witness) = witness {
                return Err(failure(
                    query,
                    source,
                    ResolveErrorKind::SourceSettingsConflict,
                    Some(witness),
                    Some(entry.location),
                ));
            }
            if settings.extended.is_none() && other.extended.is_some() {
                settings.extended = other.extended;
                extended_evidence = entry.location;
            }
        }
        self.check_special(query, declared.unit_index, source)?;
        if let Some(entry) = self
            .source_declarations(query.segment, source)
            .find(|entry| matches!(entry.declaration, SourceDeclaration::Acpi(_)))
        {
            return Err(failure(
                query,
                source,
                ResolveErrorKind::AcpiSourceRequiresIdentity,
                Some(declared.evidence),
                Some(entry.location),
            ));
        }
        Ok(settings)
    }

    fn check_special(
        &self,
        query: Query,
        unit_index: u16,
        source: u16,
    ) -> Result<(), ResolveError> {
        for entry in self.source_declarations(query.segment, source) {
            let SourceDeclaration::Special(device) = entry.declaration else { continue };
            // Equal duplicates are evidence, but one identity must not change
            // its source or unit in any form, even outside the selected segment.
            for (index, other) in self.ivrs.special_devices().iter().enumerate() {
                if device.handle != other.handle || device.variety != other.variety {
                    continue;
                }
                if self.unit_index(other.form_index) != unit_index
                    || other.source_id != source
                    || other.dte_settings != device.dte_settings
                {
                    return Err(failure(
                        query,
                        source,
                        ResolveErrorKind::SpecialIdentityConflict,
                        Some(entry.location),
                        Some(Evidence {
                            kind: EvidenceKind::Special,
                            index: index as u16,
                            form_index: other.form_index,
                            offset: other.offset,
                        }),
                    ));
                }
            }
            // All form types support special devices; no form is a preferred
            // authority when one adds or removes a relevant special identity.
            for (index, form) in self.ivrs.forms().iter().enumerate() {
                if form.unit_index == unit_index
                    && !self.ivrs.special_devices().iter().any(|other| {
                        usize::from(other.form_index) == index && device.same_declaration(*other)
                    })
                {
                    return Err(failure(
                        query,
                        source,
                        ResolveErrorKind::SpecialFormsDiffer,
                        Some(entry.location),
                        Some(self.form_evidence(index)),
                    ));
                }
            }
        }
        Ok(())
    }
}
