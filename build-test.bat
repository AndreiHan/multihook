rustup target add x86_64-pc-windows-msvc
cargo test --release --all-targets --all-features
cargo build --release --target x86_64-pc-windows-msvc

rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc

rustup target add aarch64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc

@RD /S /Q %~dp0\target\dist
md %~dp0\target\dist

REM copy hook_cli.exe to dist
copy /y %~dp0\target\x86_64-pc-windows-msvc\release\hook_cli.exe %~dp0\target\dist\hook_cli_x64.exe
copy /y %~dp0\target\i686-pc-windows-msvc\release\hook_cli.exe %~dp0\target\dist\hook_cli_x86.exe
copy /y %~dp0\target\aarch64-pc-windows-msvc\release\hook_cli.exe %~dp0\target\dist\hook_cli_arm64.exe

md %~dp0\target\dist\lib\
md %~dp0\target\dist\lib\x64\
md %~dp0\target\dist\lib\x86\
md %~dp0\target\dist\lib\arm64\

REM copy multi_hook.dll to dist
copy /y %~dp0\target\x86_64-pc-windows-msvc\release\multi_hook.dll %~dp0\target\dist\lib\x64\multi_hook.dll
copy /y %~dp0\target\i686-pc-windows-msvc\release\multi_hook.dll %~dp0\target\dist\lib\x86\multi_hook.dll
copy /y %~dp0\target\aarch64-pc-windows-msvc\release\multi_hook.dll %~dp0\target\dist\lib\arm64\multi_hook.dll

REM copy crash_hook.dll to dist
copy /y %~dp0\target\x86_64-pc-windows-msvc\release\crash_hook.dll %~dp0\target\dist\lib\x64\crash_hook.dll
copy /y %~dp0\target\i686-pc-windows-msvc\release\crash_hook.dll %~dp0\target\dist\lib\x86\crash_hook.dll
copy /y %~dp0\target\aarch64-pc-windows-msvc\release\crash_hook.dll %~dp0\target\dist\lib\arm64\crash_hook.dll