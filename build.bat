@echo off
setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

echo.
echo ===============================
echo Building MultiHook for x64
echo ===============================
rustup target add x86_64-pc-windows-msvc
if errorlevel 1 (
    echo ERROR: Failed to add x86_64 target.
    exit /b 1
)
cargo build --release --target x86_64-pc-windows-msvc
if errorlevel 1 (
    echo ERROR: x64 build failed.
    exit /b 1
)

echo.
echo ===============================
echo Building MultiHook for x86
echo ===============================
rustup target add i686-pc-windows-msvc
if errorlevel 1 (
    echo ERROR: Failed to add i686 target.
    exit /b 1
)
cargo build --release --target i686-pc-windows-msvc
if errorlevel 1 (
    echo ERROR: x86 build failed.
    exit /b 1
)

echo.
echo ===============================
echo Building MultiHook for arm64
echo ===============================
rustup target add aarch64-pc-windows-msvc
if errorlevel 1 (
    echo ERROR: Failed to add arm64 target.
    exit /b 1
)
cargo build --release --target aarch64-pc-windows-msvc
if errorlevel 1 (
    echo ERROR: arm64 build failed.
    exit /b 1
)

echo.
echo ===============================
echo Cleaning up previous distribution directory...
echo ===============================
if exist %~dp0target\dist (
    @RD /S /Q %~dp0target\dist
    if errorlevel 1 (
        echo ERROR: Failed to remove old dist directory.
        exit /b 1
    )
)
mkdir %~dp0target\dist 2>nul

echo.
echo ===============================
echo Preparing distribution directory...
echo ===============================

REM copy hook_cli.exe to dist
copy /y %~dp0target\x86_64-pc-windows-msvc\release\hook_cli.exe %~dp0target\dist\hook_cli_x64.exe
if errorlevel 1 (
    echo ERROR: Failed to copy hook_cli_x64.exe
    exit /b 1
)
copy /y %~dp0target\i686-pc-windows-msvc\release\hook_cli.exe %~dp0target\dist\hook_cli_x86.exe
if errorlevel 1 (
    echo ERROR: Failed to copy hook_cli_x86.exe
    exit /b 1
)
copy /y %~dp0target\aarch64-pc-windows-msvc\release\hook_cli.exe %~dp0target\dist\hook_cli_arm64.exe
if errorlevel 1 (
    echo ERROR: Failed to copy hook_cli_arm64.exe
    exit /b 1
)

mkdir %~dp0target\dist\lib 2>nul
mkdir %~dp0target\dist\lib\x64 2>nul
mkdir %~dp0target\dist\lib\x86 2>nul
mkdir %~dp0target\dist\lib\arm64 2>nul

REM copy multi_hook.dll to dist
copy /y %~dp0target\x86_64-pc-windows-msvc\release\multi_hook.dll %~dp0target\dist\lib\x64\multi_hook.dll
if errorlevel 1 (
    echo ERROR: Failed to copy multi_hook.dll x64
    exit /b 1
)
copy /y %~dp0target\i686-pc-windows-msvc\release\multi_hook.dll %~dp0target\dist\lib\x86\multi_hook.dll
if errorlevel 1 (
    echo ERROR: Failed to copy multi_hook.dll x86
    exit /b 1
)
copy /y %~dp0target\aarch64-pc-windows-msvc\release\multi_hook.dll %~dp0target\dist\lib\arm64\multi_hook.dll
if errorlevel 1 (
    echo ERROR: Failed to copy multi_hook.dll arm64
    exit /b 1
)

REM copy crash_hook.dll to dist
copy /y %~dp0target\x86_64-pc-windows-msvc\release\crash_hook.dll %~dp0target\dist\lib\x64\crash_hook.dll
if errorlevel 1 (
    echo ERROR: Failed to copy crash_hook.dll x64
    exit /b 1
)
copy /y %~dp0target\i686-pc-windows-msvc\release\crash_hook.dll %~dp0target\dist\lib\x86\crash_hook.dll
if errorlevel 1 (
    echo ERROR: Failed to copy crash_hook.dll x86
    exit /b 1
)
copy /y %~dp0target\aarch64-pc-windows-msvc\release\crash_hook.dll %~dp0target\dist\lib\arm64\crash_hook.dll
if errorlevel 1 (
    echo ERROR: Failed to copy crash_hook.dll arm64
    exit /b 1
)

echo.
echo ===============================
echo Build completed successfully!
echo Files are located in %~dp0target\dist
echo ===============================
endlocal
exit /b 0