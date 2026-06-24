//! Shell environment variables.
//!
//! A small ordered map of variable names to values, seeded with the defaults a
//! Debian login shell exports. Purely in-memory; nothing is read from the real
//! process environment.

use std::collections::BTreeMap;

/// The set of environment variables for a single shell session.
#[derive(Debug, Clone)]
pub struct Env {
    vars: BTreeMap<String, String>,
}

impl Env {
    /// Seed the default environment a Debian login shell would present for
    /// `user` whose home directory is `home`.
    pub fn login(user: &str, home: &str, hostname: &str) -> Self {
        let mut vars = BTreeMap::new();
        vars.insert("USER".into(), user.into());
        vars.insert("LOGNAME".into(), user.into());
        vars.insert("HOME".into(), home.into());
        vars.insert("PWD".into(), home.into());
        vars.insert("SHELL".into(), "/bin/bash".into());
        vars.insert(
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games".into(),
        );
        vars.insert("TERM".into(), "xterm-256color".into());
        vars.insert("LANG".into(), "en_US.UTF-8".into());
        vars.insert("MAIL".into(), format!("/var/mail/{user}"));
        vars.insert("HOSTNAME".into(), hostname.into());
        vars.insert("SHLVL".into(), "1".into());
        vars.insert("_".into(), "/usr/bin/bash".into());
        Self { vars }
    }

    /// Get a variable's value, if set.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    /// Set (or overwrite) a variable.
    pub fn set(&mut self, key: &str, value: &str) {
        const MAX_ENV_VARS: usize = 256;
        const MAX_ENV_VALUE_LEN: usize = 4096;
        if !self.vars.contains_key(key) && self.vars.len() >= MAX_ENV_VARS {
            return;
        }
        let value = value.chars().take(MAX_ENV_VALUE_LEN).collect::<String>();
        self.vars.insert(key.to_string(), value);
    }

    /// Remove a variable, returning `true` if it existed.
    pub fn unset(&mut self, key: &str) -> bool {
        self.vars.remove(key).is_some()
    }

    /// Iterate over all variables in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.vars.iter()
    }
}
