use super::terminal::{BACKSPACE, CTRL_C, CTRL_X, DELETE, ESC};
use super::MimicHandler;
use crate::shell::Screen;
use russh::keys::ssh_encoding::bytes::Bytes;
use russh::server::Session;
use russh::ChannelId;
use std::time::Duration;
/// How often a full-screen command repaints. Real `top`'s default delay.
pub(super) const SCREEN_REFRESH: Duration = Duration::from_secs(3);

/// Move the cursor home and erase what is below it — what a full-screen program
/// sends before painting a frame, so each redraw lands on top of the last.
pub(super) const SCREEN_HOME: &str = "\x1b[H\x1b[J";

/// A full-screen display or terminal hold, kept alive as long as it owns the
/// terminal. Dropping this aborts the redraw task if there is one, so a timer
/// cannot outlive the channel it paints — closing the channel, ending the
/// session, or quitting the display all stop it.
pub(super) struct ScreenHold {
    /// Which display is up, deciding how keystrokes and the quit sequence are
    /// interpreted. Nothing here re-renders on a keystroke — only `top`'s
    /// timer repaints, and it owns its own `TopScreen` — so this is all the
    /// network layer needs, not the [`Screen`] itself.
    kind: ScreenKind,
    /// `vi`'s in-progress `:`-command, accumulated since the last `:` until
    /// Enter or Esc. Always `None` outside colon-command mode, and for every
    /// kind but `Vi`.
    colon: Option<String>,
    /// `top`'s periodic repaint task. Only `Top` schedules one; every other
    /// kind paints once and holds with nothing left to do on a timer.
    redraw: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ScreenHold {
    fn drop(&mut self) {
        if let Some(redraw) = &self.redraw {
            redraw.abort();
        }
    }
}

/// Which full-screen display [`ScreenHold`] is holding the terminal with.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ScreenKind {
    Top,
    Vi,
    Nano,
    Listen,
}

/// Advance `vi`'s colon-command state on one keystroke. Returns whether it
/// just completed one of the quit commands (`q`, `q!`, `wq`, `wq!`, `x`);
/// Ctrl-C quits unconditionally, the same escape hatch every screen kind has.
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
    /// Take over the terminal with a full-screen display, repainting it every
    /// [`SCREEN_REFRESH`] until the client quits.
    ///
    /// The emulation layers own no clock, so the display arrives as a value
    /// that can render itself at any instant and the timer lives here. The task
    /// holds a session handle rather than a borrow of the shell, and stops on
    /// the first write that fails — which is what a closed session looks like
    /// from the outside — so it cannot outlive the connection even if nothing
    /// aborts it first.
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
                    // The first tick fires immediately; the frame above is that one.
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
                // A real listener prints nothing until a client connects,
                // which never happens here — it just holds the terminal.
                self.screen = Some(ScreenHold {
                    kind: ScreenKind::Listen,
                    colon: None,
                    redraw: None,
                });
            }
        }
        Ok(())
    }

    /// Feed a keystroke to a display holding the terminal. Returns whether the
    /// display is still up.
    ///
    /// `top` quits on `q` (and Ctrl-C, like any foreground job); `vi` quits on
    /// `:q`/`:q!`/`:wq`/`:wq!`/`:x` followed by Enter, a colon-command mode
    /// cancelled by Esc; `nano` quits on Ctrl-X; `nc -l` — a plain terminal
    /// hold with no commands of its own — quits only on Ctrl-C. Every other
    /// key is consumed by the display rather than echoed, which is the whole
    /// point of holding the screen.
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
            // Dropping the hold aborts the redraw task, if there was one.
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
            // `top`, `vi` and `nano` clear the screen on their way out, as
            // the real programs do; `nc -l` never painted one, so Ctrl-C
            // out of it looks like any other interrupted foreground
            // command instead of a display disappearing.
            ScreenKind::Listen => "^C\n",
            ScreenKind::Top | ScreenKind::Vi | ScreenKind::Nano => SCREEN_HOME,
        };
        session.data(channel, self.out(farewell))?;
        self.show_shell_prompt(channel, session)?;
        // Anything typed after the quit key is ordinary input again.
        Ok(Some(&data[quit_at + 1..]))
    }
}
