use std::fmt::Display;

use crate::output;

pub trait Warn {
    fn warn(self, msg: &str);
}

pub trait WarnResult {
    fn warn(self, msg: &str);
}

impl<T, E: Warn> WarnResult for Result<T, E> {
    fn warn(self, msg: &str) {
        if let Err(error) = self {
            error.warn(msg)
        }
    }
}

impl<T: Display> Warn for T {
    fn warn(self, msg: &str) {
        output::warning(format!("{}: {}", msg, self))
    }
}
