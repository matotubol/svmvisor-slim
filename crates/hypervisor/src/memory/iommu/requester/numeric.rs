use super::*;

pub(super) struct Numeric<'a> {
    pub scope: &'a RequesterScope,
    pub evidence: Evidence,
    pub unit_index: u16,
}

impl<'a> Resolver<'a> {
    /// Compare complete structural declarations, not just their value at one ID.
    pub(super) fn numeric(&self, query: Query, subject: u16) -> Result<Numeric<'a>, ResolveError> {
        if self.ivrs.units().is_empty() {
            return Err(failure(query, subject, ResolveErrorKind::EmptyInventory, None, None));
        }
        let mut representative: Option<Numeric<'a>> = None;
        // First establish a unique unit independently of declaration ordering.
        for (index, scope) in self.ivrs.requester_scopes().iter().enumerate() {
            if self.segment(scope.form_index) != query.segment || !scope.range.contains(subject) {
                continue;
            }
            let unit_index = self.unit_index(scope.form_index);
            let evidence = scope_evidence(index, scope);
            if let Some(prior) = &representative {
                if prior.unit_index != unit_index {
                    return Err(failure(
                        query,
                        subject,
                        ResolveErrorKind::RequesterAcrossUnits,
                        Some(prior.evidence),
                        Some(evidence),
                    ));
                }
            } else {
                representative = Some(Numeric { scope, evidence, unit_index });
            }
        }
        let Some(representative) = representative else {
            let auxiliary = self
                .source_declarations(query.segment, subject)
                .find(|entry| !matches!(entry.declaration, SourceDeclaration::Requester(_)));
            let kind = if auxiliary.is_some() {
                ResolveErrorKind::AuxiliaryIdentityRequired
            } else {
                ResolveErrorKind::NoNumericDeclaration
            };
            return Err(failure(query, subject, kind, auxiliary.map(|e| e.location), None));
        };
        // Refuse a non-identical overlap before considering differences between
        // forms. A broad range never wins over a singleton, or vice versa.
        for (form_index, form) in self.ivrs.forms().iter().enumerate() {
            if form.unit_index != representative.unit_index {
                continue;
            }
            let mut in_form: Option<Numeric<'a>> = None;
            for (index, scope) in self.ivrs.requester_scopes().iter().enumerate() {
                if usize::from(scope.form_index) != form_index || !scope.range.contains(subject) {
                    continue;
                }
                let evidence = scope_evidence(index, scope);
                if let Some(prior) = &in_form {
                    if !scope.same_declaration(*prior.scope) {
                        return Err(failure(
                            query,
                            subject,
                            ResolveErrorKind::OverlappingDeclarations,
                            Some(prior.evidence),
                            Some(evidence),
                        ));
                    }
                } else {
                    in_form =
                        Some(Numeric { scope, evidence, unit_index: representative.unit_index });
                }
            }
        }
        for (form_index, form) in self.ivrs.forms().iter().enumerate() {
            if form.unit_index != representative.unit_index {
                continue;
            }
            let in_form = self.ivrs.requester_scopes().iter().enumerate().find(|(_, scope)| {
                usize::from(scope.form_index) == form_index && scope.range.contains(subject)
            });
            let Some((index, scope)) = in_form else {
                return Err(failure(
                    query,
                    subject,
                    ResolveErrorKind::MissingFormDeclaration,
                    Some(representative.evidence),
                    Some(self.form_evidence(form_index)),
                ));
            };
            if !scope.same_declaration(*representative.scope) {
                return Err(failure(
                    query,
                    subject,
                    ResolveErrorKind::FormDeclarationsDiffer,
                    Some(representative.evidence),
                    Some(scope_evidence(index, scope)),
                ));
            }
        }
        Ok(representative)
    }

    pub(super) fn check_unit(&self, query: Query, unit_index: u16) -> Result<(), ResolveError> {
        for diagnostic in self.ivrs.diagnostics() {
            if !matches!(
                diagnostic.kind,
                DiagnosticKind::ReservedIvhdBits | DiagnosticKind::FormPropertiesDiffer
            ) {
                continue;
            }
            let form = self.ivrs.forms().iter().enumerate().find(|(_, form)| {
                form.unit_index == unit_index && form.offset == diagnostic.offset
            });
            if let Some((index, _)) = form {
                let related = diagnostic.related_offset.and_then(|offset| {
                    self.ivrs
                        .forms()
                        .iter()
                        .position(|form| form.offset == offset)
                        .map(|index| self.form_evidence(index))
                });
                return Err(failure(
                    query,
                    query.requester,
                    ResolveErrorKind::UnitDiagnostic(diagnostic.kind),
                    Some(self.form_evidence(index)),
                    related,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn check_alias_source(
        &self,
        query: Query,
        declared: &Numeric<'_>,
        source: u16,
    ) -> Result<(), ResolveError> {
        let numeric = self.numeric(query, source).map_err(|mut error| {
            if matches!(
                error.kind,
                ResolveErrorKind::NoNumericDeclaration
                    | ResolveErrorKind::AuxiliaryIdentityRequired
            ) {
                error.kind = ResolveErrorKind::AliasSourceUndeclared;
                error.second = error.first;
                error.first = Some(declared.evidence);
            }
            error
        })?;
        let kind = if numeric.unit_index != declared.unit_index {
            Some(ResolveErrorKind::SourceAcrossUnits)
        } else if numeric.scope.alias_source.is_some() {
            Some(ResolveErrorKind::AliasSourceNotDirect)
        } else {
            None
        };
        if let Some(kind) = kind {
            return Err(failure(
                query,
                source,
                kind,
                Some(declared.evidence),
                Some(numeric.evidence),
            ));
        }
        Ok(())
    }
}
