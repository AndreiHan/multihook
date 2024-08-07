use windows::Win32::{
    Foundation::HINSTANCE,
    System::SystemServices::{
        DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
    },
};

static DLL_NAME: &str = "multi_hook.dll";

#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        DLL_THREAD_ATTACH => sent_message(msg_protocol::DllReason::ThreadAttach),
        DLL_THREAD_DETACH => sent_message(msg_protocol::DllReason::ThreadDetach),
        DLL_PROCESS_DETACH => {
            sent_message(msg_protocol::DllReason::ProcessDetach);
        }
        _ => (),
    }
    true
}

fn attach() {
    let _ = dll_injector::init_dll(DLL_NAME);
    sent_message(msg_protocol::DllReason::ProcessAttach);
    println!("Unloading in 15 seconds...");
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(15));
        let status = dll_injector::unload_self(DLL_NAME, true);
        println!("Unload status: {status:?}");
    });
}

fn sent_message(reason: msg_protocol::DllReason) {
    let message = msg_protocol::DllMessage::new(reason);
    let _ = pipe_com::write_to_pipe(&message.to_string());
}
