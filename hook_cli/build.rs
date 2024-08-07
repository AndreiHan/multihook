fn main() {
    let mut res = tauri_winres::WindowsResource::new();
    res.set_icon("assets/hook.ico");
    res.compile().unwrap();
}
