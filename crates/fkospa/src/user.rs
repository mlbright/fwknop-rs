use nix::unistd::{Uid, User};

use crate::error::Error;

/// The current user's login name, the default username in an SPA message.
/// Falls back to `$USER` when the user database has no entry (as Go's
/// `os/user` does).
pub(crate) fn current_username() -> Result<String, Error> {
    match User::from_uid(Uid::current()) {
        Ok(Some(user)) => Ok(user.name),
        Ok(None) => std::env::var("USER")
            .ok()
            .filter(|u| !u.is_empty())
            .ok_or_else(|| Error::Username(format!("no user with uid {}", Uid::current()))),
        Err(e) => Err(Error::Username(e.to_string())),
    }
}
