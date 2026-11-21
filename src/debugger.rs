#[cfg(windows)]
pub fn run_debug_session(
    target: &str,
    args: Option<&str>,
    timeout_secs: u64,
) -> Result<Vec<String>, String> {
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::Diagnostics::Debug::*;
    use windows_sys::Win32::System::Threading::*;

    let mut dlls = Vec::new();

    let cmd_line = if let Some(a) = args {
        format!("\"{target}\" {a}")
    } else {
        format!("\"{target}\"")
    };

    let cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_ptr() as *mut u16,
            std::ptr::null(),
            std::ptr::null(),
            0,
            DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };

    if ok == 0 {
        return Err(format!(
            "CreateProcessW failed (error {})",
            unsafe { GetLastError() }
        ));
    }

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };

    loop {
        if start.elapsed() > timeout {
            break;
        }

        let wait_ms = timeout
            .checked_sub(start.elapsed())
            .unwrap_or_default()
            .as_millis()
            .min(1000) as u32;

        let got = unsafe { WaitForDebugEvent(&mut event, wait_ms) };
        if got == 0 {
            // Timeout on wait — check if process still alive
            let mut exit_code: u32 = 0;
            if unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code) } != 0
                && exit_code != 259
            // STILL_ACTIVE
            {
                break;
            }
            continue;
        }

        let continue_status = match event.dwDebugEventCode {
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { &event.u.LoadDll };
                if let Some(path) = get_dll_path(info.hFile, pi.hProcess, info.lpImageName, info.fUnicode) {
                    dlls.push(path);
                }
                if !info.hFile.is_null() {
                    unsafe { CloseHandle(info.hFile) };
                }
                DBG_CONTINUE
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                unsafe {
                    ContinueDebugEvent(
                        event.dwProcessId,
                        event.dwThreadId,
                        DBG_CONTINUE,
                    )
                };
                break;
            }
            EXCEPTION_DEBUG_EVENT => {
                let exc = unsafe { &event.u.Exception };
                if exc.dwFirstChance != 0 {
                    DBG_EXCEPTION_NOT_HANDLED
                } else {
                    DBG_CONTINUE
                }
            }
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { &event.u.CreateProcessInfo };
                if !info.hFile.is_null() {
                    unsafe { CloseHandle(info.hFile) };
                }
                DBG_CONTINUE
            }
            _ => DBG_CONTINUE,
        };

        unsafe {
            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status);
        }
    }

    // Terminate if still running
    unsafe {
        TerminateProcess(pi.hProcess, 0);
        // Drain remaining debug events
        while WaitForDebugEvent(&mut event, 100) != 0 {
            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    Ok(dlls)
}

#[cfg(windows)]
fn get_dll_path(
    h_file: windows_sys::Win32::Foundation::HANDLE,
    h_process: windows_sys::Win32::Foundation::HANDLE,
    lp_image_name: *const core::ffi::c_void,
    f_unicode: u16,
) -> Option<String> {
    // Method 1: GetFinalPathNameByHandleW
    if !h_file.is_null() {
        let mut buf = [0u16; 520];
        let len = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(
                h_file,
                buf.as_mut_ptr(),
                520,
                0,
            )
        };
        if len > 0 && (len as usize) < 520 {
            let path = String::from_utf16_lossy(&buf[..len as usize]);
            // Strip \\?\ prefix
            let path = path
                .strip_prefix("\\\\?\\")
                .unwrap_or(&path)
                .to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }

    // Method 2: ReadProcessMemory on lpImageName
    if !lp_image_name.is_null() {
        let mut name_ptr: usize = 0;
        let mut bytes_read: usize = 0;
        let ok = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                h_process,
                lp_image_name,
                &mut name_ptr as *mut usize as *mut core::ffi::c_void,
                std::mem::size_of::<usize>(),
                &mut bytes_read,
            )
        };
        if ok != 0 && name_ptr != 0 {
            if f_unicode != 0 {
                let mut buf = [0u16; 520];
                let ok = unsafe {
                    windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                        h_process,
                        name_ptr as *const core::ffi::c_void,
                        buf.as_mut_ptr() as *mut core::ffi::c_void,
                        1040,
                        &mut bytes_read,
                    )
                };
                if ok != 0 {
                    let len = buf.iter().position(|&c| c == 0).unwrap_or(520);
                    let path = String::from_utf16_lossy(&buf[..len]);
                    if !path.is_empty() {
                        return Some(path);
                    }
                }
            } else {
                let mut buf = [0u8; 520];
                let ok = unsafe {
                    windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                        h_process,
                        name_ptr as *const core::ffi::c_void,
                        buf.as_mut_ptr() as *mut core::ffi::c_void,
                        520,
                        &mut bytes_read,
                    )
                };
                if ok != 0 {
                    let len = buf.iter().position(|&c| c == 0).unwrap_or(520);
                    let path = String::from_utf8_lossy(&buf[..len]).to_string();
                    if !path.is_empty() {
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}

#[cfg(not(windows))]
pub fn run_debug_session(
    _target: &str,
    _args: Option<&str>,
    _timeout_secs: u64,
) -> Result<Vec<String>, String> {
    Err("dynamic analysis requires Windows".into())
}
