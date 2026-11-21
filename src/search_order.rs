use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum HijackClass {
    Missing,
    Phantom,
    WritablePath,
    Sideload,
    KnownDll,
    Safe,
}

impl std::fmt::Display for HijackClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HijackClass::Missing => write!(f, "MISSING"),
            HijackClass::Phantom => write!(f, "PHANTOM"),
            HijackClass::WritablePath => write!(f, "WRITABLE_PATH"),
            HijackClass::Sideload => write!(f, "SIDELOAD"),
            HijackClass::KnownDll => write!(f, "KNOWN_DLL"),
            HijackClass::Safe => write!(f, "SAFE"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DllFinding {
    pub dll_name: String,
    pub class: HijackClass,
    pub found_path: Option<String>,
    pub app_dir_writable: bool,
    pub source: String,
    pub details: String,
}

pub fn get_search_dirs(app_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // 1. Application directory
    dirs.push(app_dir.to_path_buf());

    // 2. System directory
    #[cfg(windows)]
    {
        let mut buf = [0u16; 260];
        unsafe {
            let len =
                windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
                    buf.as_mut_ptr(),
                    260,
                );
            if len > 0 {
                dirs.push(PathBuf::from(String::from_utf16_lossy(
                    &buf[..len as usize],
                )));
            }
        }
    }
    #[cfg(not(windows))]
    {
        dirs.push(PathBuf::from("C:\\Windows\\System32"));
    }

    // 3. 16-bit system directory (System32 on modern Windows — skip, same as above)

    // 4. Windows directory
    #[cfg(windows)]
    {
        let mut buf = [0u16; 260];
        unsafe {
            let len =
                windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
                    buf.as_mut_ptr(),
                    260,
                );
            if len > 0 {
                dirs.push(PathBuf::from(String::from_utf16_lossy(
                    &buf[..len as usize],
                )));
            }
        }
    }
    #[cfg(not(windows))]
    {
        dirs.push(PathBuf::from("C:\\Windows"));
    }

    // 5. Current directory
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }

    // 6. PATH directories
    if let Ok(path_var) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path_var.split(sep) {
            let p = PathBuf::from(dir);
            if p.is_absolute() {
                dirs.push(p);
            }
        }
    }

    dirs
}

pub fn is_api_set(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("api-ms-win-")
        || lower.starts_with("ext-ms-win-")
        || lower.starts_with("api-ms-onecoreuap-")
}

pub fn is_dir_writable(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    let probe = dir.join(".cradle_write_test");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

pub fn classify_dll(
    dll_name: &str,
    search_dirs: &[PathBuf],
    known_dlls: &HashSet<String>,
    app_dir: &Path,
    app_dir_writable: bool,
) -> DllFinding {
    let lower = dll_name.to_lowercase();

    if is_api_set(&lower) {
        return DllFinding {
            dll_name: dll_name.to_string(),
            class: HijackClass::Safe,
            found_path: None,
            app_dir_writable,
            source: String::new(),
            details: "API set — virtual, not a real DLL".into(),
        };
    }

    if known_dlls.contains(&lower) {
        return DllFinding {
            dll_name: dll_name.to_string(),
            class: HijackClass::KnownDll,
            found_path: Some(format!("C:\\Windows\\System32\\{lower}")),
            app_dir_writable,
            source: String::new(),
            details: "Protected by KnownDLLs — always loads from System32".into(),
        };
    }

    // Walk search order
    for dir in search_dirs {
        let candidate = dir.join(&lower);
        if candidate.exists() {
            let is_app_dir = same_dir(dir, app_dir);

            if is_app_dir {
                if app_dir_writable {
                    return DllFinding {
                        dll_name: dll_name.to_string(),
                        class: HijackClass::Sideload,
                        found_path: Some(candidate.display().to_string()),
                        app_dir_writable,
                        source: String::new(),
                        details: format!(
                            "Found in writable app dir — replace with proxy DLL"
                        ),
                    };
                }
                return DllFinding {
                    dll_name: dll_name.to_string(),
                    class: HijackClass::Safe,
                    found_path: Some(candidate.display().to_string()),
                    app_dir_writable,
                    source: String::new(),
                    details: "In app dir but dir is not writable".into(),
                };
            }

            // Found in a non-app-dir location
            if app_dir_writable {
                return DllFinding {
                    dll_name: dll_name.to_string(),
                    class: HijackClass::Phantom,
                    found_path: Some(candidate.display().to_string()),
                    app_dir_writable,
                    source: String::new(),
                    details: format!(
                        "Loaded from {} — plant in writable app dir to hijack",
                        dir.display()
                    ),
                };
            }

            if is_dir_writable(dir) {
                return DllFinding {
                    dll_name: dll_name.to_string(),
                    class: HijackClass::WritablePath,
                    found_path: Some(candidate.display().to_string()),
                    app_dir_writable,
                    source: String::new(),
                    details: format!(
                        "Loaded from writable dir {} — replace in place",
                        dir.display()
                    ),
                };
            }

            return DllFinding {
                dll_name: dll_name.to_string(),
                class: HijackClass::Safe,
                found_path: Some(candidate.display().to_string()),
                app_dir_writable,
                source: String::new(),
                details: format!("Found in {} (not writable)", dir.display()),
            };
        }
    }

    // Not found anywhere
    DllFinding {
        dll_name: dll_name.to_string(),
        class: HijackClass::Missing,
        found_path: None,
        app_dir_writable,
        source: String::new(),
        details: "Not found in any search path — drop in app dir".into(),
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}
