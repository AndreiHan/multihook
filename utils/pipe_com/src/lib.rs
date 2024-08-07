#[macro_use]
extern crate log;

use std::{
    ffi::c_void,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time,
};

use anyhow::{anyhow, Result};
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE},
        Storage::FileSystem::{
            CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE,
            OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
        },
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, SetNamedPipeHandleState, WaitNamedPipeW,
            PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        },
    },
};

const PIPE_NAME: &str = "\\\\.\\pipe\\multihookpipe";

#[allow(dead_code)]
struct SafeHandle(*mut c_void);

unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

#[derive(Debug)]
pub struct ThreadResults {
    thread_list: Vec<JoinHandle<Result<String>>>,
}

impl ThreadResults {
    /// Retrieves the results from the monitor threads, with an optional timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - An optional timeout in seconds to wait for the threads to finish.
    ///
    /// # Returns
    ///
    /// A `Vec<String>` containing the results of the threads.
    ///
    /// # Panics
    ///
    /// This function will panic if it fails to join a thread or if the thread's result is an error.
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn retrieve_results(self, provided_timeout: Option<u32>) -> Vec<msg_protocol::DllMessage> {
        let mut results: Vec<msg_protocol::DllMessage> = Vec::new();
        let mut handle_list = self.thread_list;
        let total_threads = handle_list.len();

        let provided_timeout = provided_timeout.unwrap_or(30);
        let timeout = time::Instant::now() + time::Duration::from_secs(u64::from(provided_timeout));

        info!("Waiting for threads to finish... | timeout: {provided_timeout:?}s");
        while timeout > time::Instant::now() {
            let mut i = 0;
            while i < handle_list.len() {
                if !handle_list[i].is_finished() {
                    i += 1;
                    continue;
                }

                let handle = handle_list.remove(i);
                let handle = match handle.join() {
                    Ok(handle) => handle,
                    Err(err) => {
                        error!("Error while joining thread: {err:?}");
                        continue;
                    }
                };

                let data = match handle {
                    Ok(d) => d,
                    Err(err) => {
                        error!("Thread returned error: {err:?}");
                        continue;
                    }
                };

                match msg_protocol::get_dll_message(&data) {
                    Ok(message) => {
                        results.push(message.clone());
                        if message.reason == msg_protocol::DllReason::ProcessDetach {
                            info!("Received ProcessDetach in message");
                            return results;
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse message: {e:?}");
                        error!("Data: {data}");
                    }
                }
                info!(
                    "Progress: {:.2}%",
                    ((total_threads - handle_list.len()) as f64 / total_threads as f64) * 100.0
                );
            }
            if handle_list.is_empty() {
                break;
            }
        }
        if handle_list.is_empty() {
            info!("Finished waiting for threads");
        } else {
            info!("Timed out waiting for threads");
        }
        results
    }
}

/// Starts the monitor with the specified maximum number of instances.
///
/// # Arguments
///
/// * `max_instances` - An optional maximum number of instances to start.
///
/// # Returns
///
/// A `ThreadResults` struct containing the results of the threads.
///
/// # Panics
///
/// This function will panic if it fails to lock the mutex when creating the named pipe.
#[must_use]
pub fn start_monitor(max_instances: Option<u32>) -> ThreadResults {
    let mut thread_list: Vec<JoinHandle<Result<String>>> = Vec::new();

    debug!("Starting monitor thread");
    unsafe {
        for _ in 0..max_instances.unwrap_or(1) {
            let pipe_name = HSTRING::from(PIPE_NAME);
            let named_pipe = CreateNamedPipeW(
                PCWSTR::from_raw(pipe_name.as_wide().as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                max_instances.unwrap_or(PIPE_UNLIMITED_INSTANCES),
                0,
                0,
                0,
                None,
            );

            if named_pipe.is_invalid() {
                error!("Failed to create named pipe");
                return ThreadResults { thread_list };
            }
            let moved_handle = Arc::new(Mutex::new(SafeHandle(named_pipe.0)));
            thread_list.push(std::thread::spawn(move || {
                let pipe = HANDLE(moved_handle.lock().unwrap().0);
                debug!("Waiting for connection...");
                if let Ok(()) = ConnectNamedPipe(pipe, None) {
                    debug!("Received connection to named pipe");
                    monitor_connection(pipe).join().unwrap()
                } else {
                    debug!("Failed to receive connection to named pipe");
                    let status = CloseHandle(pipe);
                    debug!("Close connection to named pipe handle status: {status:?}");
                    Err(anyhow!("Failed to receive connection to named pipe"))
                }
            }));
        }
    }
    ThreadResults { thread_list }
}

unsafe fn monitor_connection(pipe: HANDLE) -> JoinHandle<Result<String>> {
    debug!("Established connection");
    let moved_pipe = Arc::new(Mutex::new(SafeHandle(pipe.0)));
    std::thread::spawn(move || loop {
        let mut buffer = [0u8; 1024];

        let pipe = moved_pipe.lock().unwrap();
        let data = match ReadFile(HANDLE(pipe.0), Some(&mut buffer), None, None) {
            Ok(()) => {
                let data = String::from_utf8(buffer.to_vec())?
                    .trim_matches(char::from(0))
                    .to_owned();
                data
            }
            Err(err) => {
                error!("Failed to read from pipe: {err:?}");
                continue;
            }
        };
        let status = CloseHandle(HANDLE(pipe.0));
        debug!("Close connection to named pipe handle status: {status:?}");
        debug!("Data: {data}");
        return Ok(data);
    })
}

/// Writes data to a named pipe.
///
/// # Arguments
///
/// * `data` - The data to be written to the pipe.
///
/// # Returns
///
/// A `Result<()>` indicating success or failure.
///
/// # Errors
///
/// This function will return an error if the pipe cannot be opened, if the write operation fails,
/// or if there are any issues with the pipe communication.
pub fn write_to_pipe(data: &str) -> Result<()> {
    let mut dw_written: u32 = 0;
    let pipe_name = HSTRING::from(PIPE_NAME);
    unsafe {
        let _ = WaitNamedPipeW(PCWSTR::from_raw(pipe_name.as_wide().as_ptr()), 30000);
        let h_pipe = match CreateFileW(
            PCWSTR::from_raw(pipe_name.as_wide().as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) {
            Ok(handle) => {
                debug!("Connected to pipe: {pipe_name:?}");
                handle
            }
            Err(err) => {
                error!("Failed to connect to pipe: {err:?}");
                return Err(anyhow!("Failed to connect to pipe: {:?}", err));
            }
        };

        let mode = PIPE_READMODE_MESSAGE;
        match SetNamedPipeHandleState(h_pipe, Some(std::ptr::from_ref(&mode)), None, None) {
            Ok(()) => {
                debug!("Set pipe mode");
            }
            Err(err) => {
                error!("Failed to set pipe mode: {err:?}");
                let status = CloseHandle(h_pipe);
                debug!("Close connection to named pipe handle status: {status:?}");
                return Err(anyhow!("Failed to set pipe mode"));
            }
        }

        match WriteFile(h_pipe, Some(data.as_bytes()), Some(&mut dw_written), None) {
            Ok(()) => {
                debug!("Wrote to pipe: {data:?}");
            }
            Err(err) => {
                error!("Failed to write to pipe: {err:?}");
            }
        }
        let status = CloseHandle(h_pipe);
        debug!("Close connection to named pipe handle status: {status:?}");
        Ok(())
    }
}
