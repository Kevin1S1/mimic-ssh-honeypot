use std::borrow::Cow;
use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::OnceLock;

const DEFAULT_SENSOR_NAME: &str = "mimic";
const UNSET_BOOT_ID: &str = "0000000000000000";
const MAX_BYTE_ESCAPE: u32 = 0xff;
const ESCAPE_HEADROOM: usize = 8;

static SENSOR_NAME: OnceLock<String> = OnceLock::new();
static BOOT_ID: OnceLock<String> = OnceLock::new();

pub fn init(name: &str) {
    SENSOR_NAME
        .set(name.to_owned())
        .expect("event::init called more than once");

    BOOT_ID
        .set(format!("{:016x}", rand::random::<u64>()))
        .expect("event::init called more than once");
}

fn sensor_name() -> &'static str {
    SENSOR_NAME
        .get()
        .map_or(DEFAULT_SENSOR_NAME, |s| s.as_str())
}

fn boot_id() -> &'static str {
    BOOT_ID.get().map_or(UNSET_BOOT_ID, |s| s.as_str())
}

fn peer_parts(peer: SocketAddr) -> (String, u16) {
    (peer.ip().to_string(), peer.port())
}

fn needs_escape(c: char) -> bool {
    (c.is_control() && !matches!(c, '\t' | '\n' | '\r')) || c == '\x7f' || is_bidi_or_separator(c)
}

// Unicode bidirectional-override / isolate controls and the line/paragraph
// separators. None are `is_control()` in Rust, so they would otherwise pass
// through: the bidi controls let a log line reorder as rendered in a terminal
// (spoofing), and U+2028/U+2029 split a record for consumers that treat them as
// line boundaries.
fn is_bidi_or_separator(c: char) -> bool {
    matches!(c,
        '\u{200e}' | '\u{200f}'        // LRM, RLM
        | '\u{202a}'..='\u{202e}'      // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}'      // LRI, RLI, FSI, PDI
        | '\u{2028}' | '\u{2029}'      // line separator, paragraph separator
    )
}

pub fn sanitise_field(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + ESCAPE_HEADROOM);
    for c in s.chars() {
        if !needs_escape(c) {
            out.push(c);
            continue;
        }
        let u = c as u32;
        if u <= MAX_BYTE_ESCAPE {
            let _ = write!(out, "\\x{u:02x}");
        } else {
            let _ = write!(out, "\\u{{{u:x}}}");
        }
    }
    Cow::Owned(out)
}

const EVENT_KIND: &str = "event";
const EVENT_CATEGORY: &str = "intrusion_detection";
const EVENT_DATASET: &str = "mimic.ssh";
const ECS_VERSION: &str = "8.11.0";

macro_rules! emit {
    ($level:ident, $event:literal, $($rest:tt)*) => {
        tracing::$level!(
            event = $event,
            sensor_name = $crate::logging::event::sensor_name(),
            boot_id = $crate::logging::event::boot_id(),
            event_kind = $crate::logging::event::EVENT_KIND,
            event_category = $crate::logging::event::EVENT_CATEGORY,
            event_dataset = $crate::logging::event::EVENT_DATASET,
            ecs_version = $crate::logging::event::ECS_VERSION,
            $($rest)*
        )
    };
}

mod activity;
mod auth;
mod connection;
mod quarantine;
mod service;

pub use activity::{command, download, subsystem_request, CommandSource};
pub use auth::auth_attempt;
pub use connection::{
    client_banner, connection_closed, connection_opened, connection_rejected, login_timeout,
    session_timeout,
};
pub use quarantine::{quarantine_error, quarantine_global_cap, quarantine_session_cap, upload};
pub use service::{accept_error, listening, log_retention_pruned, shutdown};

#[cfg(test)]
mod tests;
