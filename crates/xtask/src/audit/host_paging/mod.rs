//! Verify global translations are retired before selecting the private host root.

use crate::{
    audit::{instruction, label, lines, normalized},
    json::Value,
};

const ENTER: &str = "svmvisor_resident_enter";
const PAGING: &str = "svmvisor_resident_host_paging";
const END: &str = "svmvisor_resident_host_paging_end";
const RUN: &str = "svmvisor_resident_vmrun";
const SWITCH: &[&str] = &[
    "movq %cr4, %rax",
    "andq $-0x81, %rax",
    "movq %rax, %cr4",
    "movq 0x8(%r10), %rax",
    "movq %rax, %cr3",
];

/// MOV CR3 preserves global translations. Pin the host-only PGE clear before
/// that load, without a PGE restore or intervening operation, before the first
/// call or VMRUN in the nonreturning entry (APM2 physical pages 220-222,591).
/// The guest CR4 capture and private-root construction have separate owners;
/// this linked-instruction audit neither executes nor models hardware TLBs.
pub fn audit_host_paging(text: &str) -> Result<Value, String> {
    let mut owner = None;
    let mut labels = Vec::new();
    let mut body = Vec::new();
    let mut premature_operation = false;
    for line in lines(text) {
        if let Some(name) = label(line) {
            owner = Some(name);
            labels.push(name);
        } else if let Some(raw) = instruction(line) {
            let value = normalized(raw.split('#').next().unwrap_or(raw));
            if labels.contains(&ENTER) && !labels.contains(&END) {
                premature_operation |= value.starts_with("call") || value == "vmrun";
                // A direct branch to the end would skip the required transition.
                premature_operation |= value.contains(&format!("<{END}"));
            }
            if owner == Some(PAGING) {
                body.push(value);
            }
        }
    }
    let position = |name| labels.iter().position(|&label| label == name);
    let ordered = match (position(ENTER), position(PAGING), position(END), position(RUN)) {
        (Some(enter), Some(paging), Some(end), Some(run)) => {
            enter < paging && paging + 1 == end && end < run
        }
        _ => false,
    };
    let unique = [ENTER, PAGING, END, RUN]
        .into_iter()
        .all(|name| labels.iter().filter(|&&label| label == name).count() == 1);
    if !ordered || !unique || premature_operation || body != SWITCH {
        return Err("host PGE is not cleared before the private CR3 switch and first entry".into());
    }
    Ok(Value::Map(vec![
        ("symbol".into(), Value::str(PAGING)),
        ("host_pge_cleared_before_cr3".into(), Value::Bool(true)),
        ("before_first_call_and_vmrun".into(), Value::Bool(true)),
    ]))
}

#[cfg(test)]
mod tests;
