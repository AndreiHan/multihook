fn main() {
    let res = tauri_winres::WindowsResource::new();
    res.compile().unwrap();
}
