use std::collections::BTreeMap;

const MAX_ENV_VARS: usize = 256;
const MAX_ENV_KEY_LEN: usize = 256;
const MAX_ENV_VALUE_LEN: usize = 4096;
const DEFAULT_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games";
const DEFAULT_SHELL: &str = "/bin/bash";
const DEFAULT_TERM: &str = "xterm-256color";
const DEFAULT_LANG: &str = "en_US.UTF-8";

#[derive(Debug, Clone)]
pub struct Env {
    vars: BTreeMap<String, String>,
}

impl Env {
    pub fn login(user: &str, home: &str, hostname: &str) -> Self {
        let mut vars = BTreeMap::new();
        vars.insert("USER".into(), user.into());
        vars.insert("LOGNAME".into(), user.into());
        vars.insert("HOME".into(), home.into());
        vars.insert("PWD".into(), home.into());
        vars.insert("SHELL".into(), DEFAULT_SHELL.into());
        vars.insert("PATH".into(), DEFAULT_PATH.into());
        vars.insert("TERM".into(), DEFAULT_TERM.into());
        vars.insert("LANG".into(), DEFAULT_LANG.into());
        vars.insert("MAIL".into(), format!("/var/mail/{user}"));
        vars.insert("HOSTNAME".into(), hostname.into());
        vars.insert("SHLVL".into(), "1".into());
        vars.insert("_".into(), "/usr/bin/bash".into());
        Self { vars }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    pub fn set(&mut self, key: &str, value: &str) {
        // Bound the key as well as the value: an assignment from a script line
        // (which isn't length-capped the way interactive input is) could
        // otherwise store a multi-megabyte variable name.
        if key.len() > MAX_ENV_KEY_LEN {
            return;
        }
        if !self.vars.contains_key(key) && self.vars.len() >= MAX_ENV_VARS {
            return;
        }
        let value = value.chars().take(MAX_ENV_VALUE_LEN).collect::<String>();
        self.vars.insert(key.to_string(), value);
    }

    pub fn unset(&mut self, key: &str) -> bool {
        self.vars.remove(key).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.vars.iter()
    }
}
