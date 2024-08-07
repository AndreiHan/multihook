#[macro_use]
extern crate log;

use std::{
    ffi::c_void,
    mem,
    path::{Path, PathBuf},
    ptr,
};

use windows::{
    core::{s, w, HSTRING, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, GetLastError, BOOL, HMODULE},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{
                DisableThreadLibraryCalls, FreeLibraryAndExitThread, GetModuleHandleExW,
                GetModuleHandleW, GetProcAddress, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            },
            Memory::{
                VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
            },
            SystemInformation::{
                IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
                IMAGE_FILE_MACHINE_I386,
            },
            Threading::{
                CreateRemoteThread, GetExitCodeThread, IsWow64Process, IsWow64Process2,
                OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
            },
        },
    },
};

use windows_version::OsVersion;

use anyhow::{anyhow, Result};

const HOOK_DLL_NAME: &str = "multi_hook.dll";
const CRASH_DLL_NAME: &str = "crash_hook.dll";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedArch {
    X86,
    X64,
    ARM64,
}

fn get_sys_arch() -> Result<SupportedArch> {
    let sys_arch = std::env::consts::ARCH;
    match sys_arch {
        "x86" => Ok(SupportedArch::X86),
        "x86_64" => Ok(SupportedArch::X64),
        "aarch64" => Ok(SupportedArch::ARM64),
        _ => Err(anyhow!("Unsupported architecture: {sys_arch}")),
    }
}

fn get_pid_arch_new(pid: u32) -> Result<SupportedArch> {
    unsafe {
        let Ok(process_handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            error!("Failed to open process, error: {:?}", GetLastError());
            return Err(anyhow!("Failed to open process: {:?}", GetLastError()));
        };

        let mut image_file_machine = IMAGE_FILE_MACHINE::default();
        let status = IsWow64Process2(process_handle, &mut image_file_machine, None);

        let handle_status = CloseHandle(process_handle);
        debug!("Close process handle status: {handle_status:?}");

        match status {
            Ok(()) => (),
            Err(e) => {
                error!("Failed to get process architecture: {e:?}");
                return Err(anyhow!("Failed to get process architecture"));
            }
        };

        match image_file_machine {
            IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE(0) => Ok(SupportedArch::X64),
            IMAGE_FILE_MACHINE_I386 => Ok(SupportedArch::X86),
            IMAGE_FILE_MACHINE_ARM64 => Ok(SupportedArch::ARM64),
            _ => Err(anyhow!("Unsupported architecture: {image_file_machine:?}")),
        }
    }
}

fn get_pid_arch_legacy(pid: u32) -> Result<SupportedArch> {
    unsafe {
        let sys_arch = get_sys_arch()?;
        if sys_arch == SupportedArch::X86 {
            return Ok(SupportedArch::X86);
        }

        if sys_arch == SupportedArch::ARM64 {
            error!("Incorrect build versioning");
            return get_pid_arch_new(pid);
        }

        let Ok(process_handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            error!("Failed to open process");
            return Err(anyhow!("Failed to open process"));
        };

        let mut is_wow64: BOOL = BOOL(1);
        let status = IsWow64Process(process_handle, &mut is_wow64);

        let close_status = CloseHandle(process_handle);
        debug!("Close process handle status: {close_status:?}");

        match status {
            Ok(()) => (),
            Err(e) => {
                error!("Failed to get process architecture: {e:?}");
                return Err(anyhow!("Failed to get process architecture"));
            }
        };

        if is_wow64.as_bool() {
            Ok(SupportedArch::X86)
        } else {
            Ok(SupportedArch::X64)
        }
    }
}

fn get_pid_arch(pid: u32) -> Result<SupportedArch> {
    if OsVersion::current() >= OsVersion::new(10, 0, 0, 1709) {
        debug!("Can use IsWow64Process2, which is available on Windows 10, build 1709 or later.");
        get_pid_arch_new(pid)
    } else {
        debug!(
            "Cannot use IsWow64Process2, which is available on Windows 10, build 1709 or later."
        );
        get_pid_arch_legacy(pid)
    }
}

/// Gets the path to the DLL.
///
/// # Returns
///
/// A `Result<PathBuf>` containing the path to the DLL on success, or an error on failure.
///
/// # Errors
///
/// This function will return an error if:
/// - The current executable's path cannot be determined.
/// - The parent directory of the current executable cannot be determined.
pub fn get_dll_path(crash: bool, target_pid: u32) -> Result<PathBuf> {
    let path = std::env::current_exe()?;
    let path = path
        .parent()
        .ok_or(anyhow!("Failed to get parent directory"))?;

    debug!("Path: {:?}", path);

    let path = path.join("lib");

    let path = match get_pid_arch(target_pid)? {
        SupportedArch::X64 => path.join("x64"),
        SupportedArch::X86 => path.join("x86"),
        SupportedArch::ARM64 => path.join("arm64"),
    };
    let dll_name = if crash { CRASH_DLL_NAME } else { HOOK_DLL_NAME };
    Ok(path.join(dll_name))
}

fn inject_cleanup(process_handle: windows::Win32::Foundation::HANDLE, dll_path_buf: *mut c_void) {
    unsafe {
        if !dll_path_buf.is_null() {
            let status = VirtualFreeEx(process_handle, dll_path_buf, 0, MEM_RELEASE);
            debug!("Cleanup - VirtualFreeEx status: {status:?}");
        }
        let status = CloseHandle(process_handle);
        debug!("Cleanup - Close process handle status: {status:?}");
    }
}

/// Injects a DLL into a process with the specified PID.
///
/// # Arguments
///
/// * `dll_path` - The path to the DLL to be injected.
/// * `pid` - The process ID of the target process.
///
/// # Returns
///
/// A `Result<u32>` containing the thread ID of the injected DLL on success, or an error on failure.
///
/// # Errors
///
/// This function will return an error if the DLL path is invalid, if the process cannot be found,
/// or if the injection fails due to insufficient permissions or other reasons.
pub fn inject(dll_path: &Path, pid: u32) -> Result<u32> {
    let Ok(process_handle) =
        (unsafe { OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid) })
    else {
        let error = unsafe { GetLastError() };
        error!("Failed to open process, error: {error:?}");
        return Err(anyhow!("Failed to open process, error: {error:?}"));
    };

    let proc_addr = unsafe {
        GetProcAddress(
            match GetModuleHandleW(w!("Kernel32")) {
                Ok(h) => h,
                Err(e) => {
                    error!("Failed to get module handle: {e:?}");
                    inject_cleanup(process_handle, std::ptr::null_mut());
                    return Err(anyhow!("Failed to get module handle"));
                }
            },
            s!("LoadLibraryW"),
        )
    };

    let dll_path = match dll_path.canonicalize() {
        Ok(path) => HSTRING::from(path.as_path()),
        Err(e) => {
            error!("Failed to get canonical path: {e:?}");
            inject_cleanup(process_handle, std::ptr::null_mut());
            return Err(anyhow!("Failed to get canonical path"));
        }
    };
    let dll_path_buf = unsafe {
        VirtualAllocEx(
            process_handle,
            None,
            dll_path.len() * size_of::<u16>(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if dll_path_buf.is_null() {
        error!(
            "Failed to allocate memory in remote process, error: {:?}",
            unsafe { GetLastError() }
        );
        inject_cleanup(process_handle, std::ptr::null_mut());
        return Err(anyhow!("Failed to allocate memory in remote process"));
    }

    unsafe {
        match WriteProcessMemory(
            process_handle,
            dll_path_buf,
            dll_path.as_ptr().cast::<c_void>(),
            dll_path.len() * size_of::<u16>(),
            None,
        ) {
            Ok(()) => (),
            Err(e) => {
                error!("Failed to write process memory: {e:?}");
                inject_cleanup(process_handle, std::ptr::null_mut());
                return Err(anyhow!("Failed to write process memory"));
            }
        }
    };

    let thread = unsafe {
        match CreateRemoteThread(
            process_handle,
            None,
            0,
            proc_addr.map(|proc_addr| {
                mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(proc_addr)
            }),
            Some(dll_path_buf),
            0,
            None,
        ) {
            Ok(thread) => thread,
            Err(e) => {
                error!("Failed to create remote thread: {e:?}");
                inject_cleanup(process_handle, std::ptr::null_mut());
                return Err(anyhow!("Failed to create remote thread"));
            }
        }
    };

    unsafe {
        WaitForSingleObject(thread, 30000);
        let mut exit_code = 0u32;

        let status = GetExitCodeThread(thread, std::ptr::from_mut::<u32>(&mut exit_code));
        debug!("GetExitCodeThread status: {status:?}");

        let status = CloseHandle(thread);
        debug!("Close thread handle status: {status:?}");

        inject_cleanup(process_handle, dll_path_buf);

        if exit_code == 0 {
            error!("Failed to inject DLL");
            return Err(anyhow!("Failed to inject DLL"));
        }
        Ok(exit_code)
    }
}

/// Retrieves the module handle for the specified DLL.
///
/// # Arguments
///
/// * `dll_name` - The name of the DLL to retrieve the module handle for.
///
/// # Errors
///
/// Returns an error if the DLL cannot be found or if there is an issue
/// retrieving the module handle.
pub fn get_module(dll_name: &str, custom_flag: Option<u32>) -> Result<HMODULE> {
    let name = HSTRING::from(dll_name);
    let address = PCWSTR::from_raw(name.as_wide().as_ptr());
    unsafe {
        let mut h_module = HMODULE::default();
        GetModuleHandleExW(
            custom_flag.unwrap_or(0),
            address,
            ptr::from_mut(&mut h_module),
        )?;
        Ok(h_module)
    }
}

/// Unloads the current DLL from the process.
///
/// # Errors
///
/// This function will return an error if:
/// - The file name of the executable cannot be obtained.
/// - The module handle cannot be retrieved.
/// - The library cannot be freed.
#[inline]
pub fn unload_self(dll_name: &str, force: bool) -> Result<()> {
    unsafe {
        let module: HMODULE = if force {
            get_module(dll_name, Some(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT))?
        } else {
            get_module(dll_name, None)?
        };
        FreeLibraryAndExitThread(module, 0);
    }
}

/// Called by the DLL to initialize itself.
///
/// # Arguments
///
/// * `dll_name` - The name of the DLL to initialize.
///
/// # Errors
///
/// Returns an error if the module handle cannot be retrieved.
#[inline]
pub fn init_dll(dll_name: &str) -> Result<()> {
    unsafe {
        let handle = get_module(dll_name, Some(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT))?;
        let status = DisableThreadLibraryCalls(handle);
        println!("DisableThreadLibraryCalls: {status:?}");
    }
    Ok(())
}
