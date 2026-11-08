use std::cmp::Ordering;

use super::{has_flag_letter, newline_terminated, split_args, with_input};
use crate::commands::CommandResult;
use crate::shell::Shell;

pub fn sort(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let reverse = has_flag_letter(&flags, 'r');
    let numeric = has_flag_letter(&flags, 'n');
    let unique = has_flag_letter(&flags, 'u');

    with_input(shell, "sort", &operands, |text| {
        let mut lines: Vec<&str> = text.lines().collect();
        if numeric {
            lines.sort_by(compare_numerically);
        } else {
            lines.sort_unstable();
        }
        if reverse {
            lines.reverse();
        }
        if unique {
            lines.dedup();
        }
        CommandResult::ok(newline_terminated(lines))
    })
}

fn compare_numerically(a: &&str, b: &&str) -> Ordering {
    numeric_key(a)
        .partial_cmp(&numeric_key(b))
        .unwrap_or(Ordering::Equal)
}

fn numeric_key(line: &str) -> f64 {
    line.trim().parse().unwrap_or(f64::MIN)
}

pub fn uniq(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let count = has_flag_letter(&flags, 'c');
    let only_dupes = has_flag_letter(&flags, 'd');
    let only_unique = has_flag_letter(&flags, 'u');

    with_input(shell, "uniq", &operands, |text| {
        let mut out = String::new();
        for (line, n) in runs(text) {
            if (only_dupes && n < 2) || (only_unique && n > 1) {
                continue;
            }
            if count {
                out.push_str(&format!("{n:>7} {line}\n"));
            } else {
                out.push_str(&format!("{line}\n"));
            }
        }
        CommandResult::ok(out)
    })
}

fn runs(text: &str) -> Vec<(&str, usize)> {
    let mut runs: Vec<(&str, usize)> = Vec::new();
    for line in text.lines() {
        match runs.last_mut() {
            Some((prev, n)) if *prev == line => *n += 1,
            _ => runs.push((line, 1)),
        }
    }
    runs
}

pub fn rev(shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    with_input(shell, "rev", &operands, |text| {
        let reversed = text
            .lines()
            .map(|line| line.chars().rev().collect::<String>());
        CommandResult::ok(newline_terminated(reversed))
    })
}

pub fn nl(shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    with_input(shell, "nl", &operands, |text| {
        let mut out = String::new();
        let mut n = 0;
        for line in text.lines() {
            if line.trim().is_empty() {
                out.push('\n');
            } else {
                n += 1;
                out.push_str(&format!("{n:>6}\t{line}\n"));
            }
        }
        CommandResult::ok(out)
    })
}
