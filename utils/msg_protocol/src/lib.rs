#[macro_use]
extern crate log;

use std::{env, fmt, process};

use anyhow::{anyhow, Result};
use chrono::{Timelike, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DllReason {
    ProcessAttach,
    ProcessDetach,
    ThreadAttach,
    ThreadDetach,
    Unknown,
}

impl fmt::Display for DllReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason_str = match self {
            DllReason::ProcessAttach => "DLL_PROCESS_ATTACH",
            DllReason::ProcessDetach => "DLL_PROCESS_DETACH",
            DllReason::ThreadAttach => "DLL_THREAD_ATTACH",
            DllReason::ThreadDetach => "DLL_THREAD_DETACH",
            DllReason::Unknown => "UNKNOWN",
        };
        write!(f, "{reason_str}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllMessage {
    pub pid: u32,
    pub process_name: String,
    pub date: String,
    pub reason: DllReason,
    pub extra: String,
}

impl Default for DllMessage {
    fn default() -> Self {
        let dt = Utc::now();
        let process_name = match env::current_exe() {
            Ok(path) => match path.to_str() {
                Some(name) => name.to_string(),
                None => "Unknown".to_string(),
            },
            Err(_) => "Unknown".to_string(),
        };

        DllMessage {
            pid: process::id(),
            process_name,
            date: format!(
                "{}:{}:{}:{}",
                dt.hour(),
                dt.minute(),
                dt.second(),
                dt.nanosecond()
            ),
            reason: DllReason::Unknown,
            extra: String::new(),
        }
    }
}

impl fmt::Display for DllMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl DllMessage {
    #[must_use]
    pub fn new(reason: DllReason) -> Self {
        DllMessage {
            reason,
            ..Default::default()
        }
    }
}

/// Parses a JSON string into a `DllMessage`.
///
/// # Errors
///
/// This function will return an error if the input string is not a valid JSON representation
/// of a `DllMessage`.
pub fn get_dll_message(data: &str) -> Result<DllMessage> {
    match serde_json::from_str(data) {
        Ok(message) => Ok(message),
        Err(e) => {
            error!("Failed to parse message: {e:?}");
            Err(anyhow!("Failed to parse message"))
        }
    }
}
