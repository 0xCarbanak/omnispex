use std::collections::HashSet;

// DLLs mapped by the kernel or loaded by ntdll before the standard search
// order is consulted. These cannot be hijacked via search order regardless
// of directory permissions. ntdll.dll is NOT in the KnownDLLs registry key
// because it's mapped directly by the kernel during process creation.
const LOADER_CRITICAL: &[&str] = &[
    "ntdll.dll",
    "kernelbase.dll",
    "ucrtbase.dll",
    "msvcp_win.dll",
    "win32u.dll",
    "gdi32full.dll",
    "bcryptprimitives.dll",
    "cryptbase.dll",
    "sspicli.dll",
    "kernel.appcore.dll",
    "apphelp.dll",
];

pub fn loader_critical_dlls() -> HashSet<String> {
    LOADER_CRITICAL.iter().map(|s| s.to_string()).collect()
}

#[cfg(windows)]
pub fn load_known_dlls() -> HashSet<String> {
    use windows_sys::Win32::System::Registry::*;

    let mut known = HashSet::new();
    let path: Vec<u16> =
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs\0"
            .encode_utf16()
            .collect();

    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        let res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key);
        if res != 0 {
            return known;
        }

        let mut index: u32 = 0;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len: u32 = 256;
            let mut data_buf = [0u16; 512];
            let mut data_len: u32 = 1024;
            let mut val_type: u32 = 0;

            let res = RegEnumValueW(
                key,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut val_type,
                data_buf.as_mut_ptr() as *mut u8,
                &mut data_len,
            );

            if res != 0 {
                break;
            }

            // REG_SZ = 1
            if val_type == 1 {
                let chars = data_len as usize / 2;
                let s = String::from_utf16_lossy(&data_buf[..chars]);
                let s = s.trim_end_matches('\0').to_lowercase();
                if !s.is_empty() {
                    known.insert(s);
                }
            }

            index += 1;
        }

        RegCloseKey(key);
    }

    known
}

#[cfg(not(windows))]
pub fn load_known_dlls() -> HashSet<String> {
    // Common KnownDLLs on Windows 10/11 for offline analysis
    let known = [
        "advapi32.dll",
        "clbcatq.dll",
        "combase.dll",
        "coml2.dll",
        "comdlg32.dll",
        "difxapi.dll",
        "gdi32.dll",
        "gdiplus.dll",
        "imagehlp.dll",
        "imm32.dll",
        "kernel32.dll",
        "msctf.dll",
        "msvcrt.dll",
        "normaliz.dll",
        "nsi.dll",
        "ntdll.dll",
        "ole32.dll",
        "oleaut32.dll",
        "psapi.dll",
        "rpcrt4.dll",
        "sechost.dll",
        "setupapi.dll",
        "shell32.dll",
        "shlwapi.dll",
        "user32.dll",
        "wldap32.dll",
        "wow64.dll",
        "wow64cpu.dll",
        "wow64win.dll",
        "ws2_32.dll",
    ];
    known.iter().map(|s| s.to_string()).collect()
}
