use super::terminal::{BACKSPACE, CTRL_C, CTRL_X, DELETE, ESC};
use super::MimicHandler;
use crate::shell::Screen;
use russh::keys::ssh_encoding::bytes::Bytes;
use russh::server::Session;
use russh::ChannelId;
use std::time::Duration;

pub(super) const SCREEN_REFRESH: Duration = Duration::from_secs(3);

pub(super) const SCREEN_HOME: &str = "\x1b[H\x1b[J";

pub(super) struct ScreenHold {
    kind: ScreenKind,

    colon: Option<String>,

    redraw: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ScreenHold {
    fn drop(&mut self) {
        if let Some(redraw) = &self.redraw {
            redraw.abort();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ScreenKind {
    Top,
    Vi,
    Nano,
    Listen,
}

pub(super) fn vi_screen_input(hold: &mut ScreenHold, byte: u8) -> bool {
    if byte == CTRL_C {
        return true;
    }
    if let Some(buf) = hold.colon.as_mut() {
        match byte {
            b'\r' | b'\n' => {
                let cmd = std::mem::take(buf);
                hold.colon = None;
                return matches!(cmd.as_str(), "q" | "q!" | "wq" | "wq!" | "x");
            }
            ESC => hold.colon = None,
            BACKSPACE | DELETE => {
                buf.pop();
            }
            0x20..=0x7e => buf.push(byte as char),
            _ => {}
        }
    } else if byte == b':' {
        hold.colon = Some(String::new());
    }
    false
}

impl MimicHandler {
    pub(super) fn hold_screen(
        &mut self,
        channel: ChannelId,
        screen: Screen,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        match screen {
            Screen::Top(top) => {
                let first = format!("{SCREEN_HOME}{}", top.render());
                session.data(channel, self.out(&first))?;
                let handle = session.handle();
                let pty = self.pty;
                let redraw = tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(SCREEN_REFRESH);

                    ticker.tick().await;
                    loop {
                        ticker.tick().await;
                        let frame = format!("{SCREEN_HOME}{}", top.render());
                        let bytes = if pty {
                            frame.replace('\n', "\r\n").into_bytes()
                        } else {
                            frame.into_bytes()
                        };
                        if handle.data(channel, Bytes::from(bytes)).await.is_err() {
                            return;
                        }
                    }
                });
                self.screen = Some(ScreenHold {
                    kind: ScreenKind::Top,
                    colon: None,
                    redraw: Some(redraw),
                });
            }
            Screen::Editor(editor) => {
                let kind = match editor.kind() {
                    crate::commands::text::EditorKind::Vi => ScreenKind::Vi,
                    crate::commands::text::EditorKind::Nano => ScreenKind::Nano,
                };
                let first = format!("{SCREEN_HOME}{}", editor.render());
                session.data(channel, self.out(&first))?;
                self.screen = Some(ScreenHold {
                    kind,
                    colon: None,
                    redraw: None,
                });
            }
            Screen::Listen => {
                self.screen = Some(ScreenHold {
                    kind: ScreenKind::Listen,
                    colon: None,
                    redraw: None,
                });
            }
        }
        Ok(())
    }

    pub(super) fn screen_input(&mut self, byte: u8) -> bool {
        let Some(hold) = self.screen.as_mut() else {
            return false;
        };
        let quit = match hold.kind {
            ScreenKind::Top => byte == b'q' || byte == CTRL_C,
            ScreenKind::Nano => byte == CTRL_X || byte == CTRL_C,
            ScreenKind::Listen => byte == CTRL_C,
            ScreenKind::Vi => vi_screen_input(hold, byte),
        };
        if quit {
            self.screen = None;
        }
        !quit
    }

    pub(super) fn feed_screen<'a>(
        &mut self,
        channel: ChannelId,
        data: &'a [u8],
        session: &mut Session,
    ) -> Result<Option<&'a [u8]>, russh::Error> {
        let Some(kind) = self.screen.as_ref().map(|hold| hold.kind) else {
            return Ok(Some(data));
        };
        let Some(quit_at) = data.iter().position(|&byte| !self.screen_input(byte)) else {
            return Ok(None);
        };
        let farewell = match kind {
            ScreenKind::Listen => "^C\n",
            ScreenKind::Top | ScreenKind::Vi | ScreenKind::Nano => SCREEN_HOME,
        };
        session.data(channel, self.out(farewell))?;
        self.show_shell_prompt(channel, session)?;

        Ok(Some(&data[quit_at + 1..]))
    }
}
