# MultiHook

A modular Rust workspace for DLL injection, process hooking, and inter-process communication on Windows.

## Overview

**MultiHook** is a Rust-based toolkit for injecting DLLs into Windows processes, monitoring process events, and testing hooks. It provides a CLI, multiple DLLs for different hook behaviors, and supporting utilities for communication and protocol handling.

## Features

- **DLL Injection**: Inject custom DLLs into target processes.
- **Process Monitoring**: Track process/thread attach/detach events.
- **Crash Testing**: Inject a DLL that intentionally crashes the target process for robustness testing.
- **Inter-Process Communication**: Uses named pipes and a custom message protocol for communication between injected DLLs and the CLI.
- **Extensible Utilities**: Modular utilities for DLL injection, message protocol, and pipe communication.

## Workspace Structure

- hook_cli — Command-line tool for injecting DLLs and monitoring events.
- multi_hook — Main DLL for process/thread event hooks.
- crash_hook — DLL that triggers a crash in the target process.
- hook_tester — Utility for testing DLL injection and hook behavior.
- pipe_com — Named pipe communication library.
- msg_protocol — Message protocol definitions and serialization.
- dll_injector — DLL injection logic and helpers.

## Usage

### Building

```sh
cargo build --release
```

Or use the provided batch scripts:

```sh
build.bat
build-test.bat
```

### CLI Example

Inject the main hook DLL into a process:

```sh
hook_cli.exe --pid <target_pid>
```

Inject the crash DLL for robustness testing:

```sh
hook_cli.exe --pid <target_pid> --crash
```

See `--help` for all options.

### Testing

Use hook_tester to simulate a process and test hook injection:

```sh
hook_tester.exe
```

## License

This project is licensed under the GNU General Public License v3.0. See LICENSE.txt for details.
