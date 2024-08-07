use windows::Win32::{
    Foundation::HINSTANCE,
    System::SystemServices::{
        DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
    },
};

static DLL_NAME: &str = "crash_hook.dll";

#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        DLL_PROCESS_DETACH => sent_message(msg_protocol::DllReason::ProcessDetach),
        DLL_THREAD_ATTACH => sent_message(msg_protocol::DllReason::ThreadAttach),
        DLL_THREAD_DETACH => sent_message(msg_protocol::DllReason::ThreadDetach),
        _ => (),
    }
    true
}

fn attach() {
    let _ = dll_injector::init_dll(DLL_NAME);
    println!("Abort in 15 seconds...");
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(15));
        let mut message = msg_protocol::DllMessage::new(msg_protocol::DllReason::ProcessAttach);
        message.extra = "crash".to_string();
        let _ = pipe_com::write_to_pipe(&message.to_string());
        std::process::abort();
    });
}

fn sent_message(reason: msg_protocol::DllReason) {
    let message = msg_protocol::DllMessage::new(reason);
    let _ = pipe_com::write_to_pipe(&message.to_string());
}
