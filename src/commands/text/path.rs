use super::{missing_operand, split_args};
use crate::commands::CommandResult;
use crate::shell::Shell;

pub fn basename(_shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    let Some(path) = operands.first() else {
        return missing_operand("basename");
    };
    let trimmed = path.trim_end_matches('/');
    let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let base = match operands.get(1) {
        Some(suffix) if base != *suffix => base.strip_suffix(*suffix).unwrap_or(base),
        _ => base,
    };
    let base = if base.is_empty() { "/" } else { base };
    CommandResult::ok(format!("{base}\n"))
}

pub fn dirname(_shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    let Some(path) = operands.first() else {
        return missing_operand("dirname");
    };
    let dir = match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) => "/",
        Some((dir, _)) => dir,
        None => ".",
    };
    CommandResult::ok(format!("{dir}\n"))
}
