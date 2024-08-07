use clap::Parser;
use std::{env::current_exe, path::PathBuf};
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::System::{LibraryLoader::LoadLibraryW, Threading::Sleep},
};

#[derive(Parser, Debug)]
#[command(version, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 30)]
    sleep_time: u64,

    #[arg(short, long, default_value_t = false)]
    d_crash_hook: bool,

    #[arg(short, long, default_value_t = String::new())]
    custom_hook: String,
}

enum HookType {
    Multi,
    Crash,
    Custom(String),
}

fn get_hook_path(hook_type: HookType) -> HSTRING {
    let current_dir = current_exe().unwrap();
    let current_dir = current_dir.parent().unwrap();
    let dll_path = match hook_type {
        HookType::Multi => current_dir.join("multi_hook.dll"),
        HookType::Crash => current_dir.join("crash_hook.dll"),
        HookType::Custom(custom_path) => {
            if custom_path.contains('\\') || custom_path.contains('/') {
                PathBuf::from(custom_path)
            } else {
                current_dir.join(custom_path)
            }
        }
    };
    HSTRING::from(dll_path.to_str().unwrap())
}

fn main() {
    let args = Args::parse();

    let dll_path: HSTRING;
    if !args.custom_hook.is_empty() {
        dll_path = get_hook_path(HookType::Custom(args.custom_hook));
    } else if args.d_crash_hook {
        dll_path = get_hook_path(HookType::Crash);
    } else {
        dll_path = get_hook_path(HookType::Multi);
    }

    unsafe {
        println!(
            "Load Status: {:?}",
            LoadLibraryW(PCWSTR::from_raw(dll_path.as_wide().as_ptr()))
        );
        Sleep(8000);
        std::thread::sleep(std::time::Duration::from_secs(args.sleep_time));
        println!("Unloading...");
    }
}
