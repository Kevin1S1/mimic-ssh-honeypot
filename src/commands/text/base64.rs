use super::{has_flag_letter, newline_terminated, split_args, with_input};
use crate::commands::CommandResult;
use crate::shell::Shell;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const SEXTET_MASK: u32 = 0x3f;
const SEXTET_BITS: u32 = 6;
const BYTE_BITS: u32 = 8;
const PADDING: char = '=';
const WRAP_COLUMNS: usize = 76;

fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextet = |shift: u32| ALPHABET[((n >> shift) & SEXTET_MASK) as usize] as char;
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { PADDING });
        out.push(if chunk.len() > 2 { sextet(0) } else { PADDING });
    }
    out
}

fn sextet_value(c: char) -> Option<u32> {
    match c {
        'A'..='Z' => Some(c as u32 - 'A' as u32),
        'a'..='z' => Some(c as u32 - 'a' as u32 + 26),
        '0'..='9' => Some(c as u32 - '0' as u32 + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => None,
    }
}

fn decode(text: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in text.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == PADDING {
            break;
        }
        acc = (acc << SEXTET_BITS) | sextet_value(c)?;
        bits += SEXTET_BITS;
        if bits >= BYTE_BITS {
            bits -= BYTE_BITS;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn base64(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let decoding = has_flag_letter(&flags, 'd');
    let unwrapped = flags.iter().any(|f| *f == "-w0" || *f == "--wrap=0");

    with_input(shell, "base64", &operands, |text| {
        if decoding {
            decode_output(text)
        } else {
            encode_output(text, unwrapped)
        }
    })
}

fn decode_output(text: &str) -> CommandResult {
    match decode(text) {
        Some(bytes) => CommandResult::ok(String::from_utf8_lossy(&bytes).into_owned()),
        None => CommandResult::err("base64: invalid input\n", 1),
    }
}

fn encode_output(text: &str, unwrapped: bool) -> CommandResult {
    let encoded = encode(text.as_bytes());
    if unwrapped {
        return CommandResult::ok(format!("{encoded}\n"));
    }
    let rows = encoded
        .as_bytes()
        .chunks(WRAP_COLUMNS)
        .map(String::from_utf8_lossy);
    CommandResult::ok(newline_terminated(rows))
}
