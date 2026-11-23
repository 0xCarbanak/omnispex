use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum HijackClass {
    Missing,
    Phantom,
    Sideload,
    KnownDll,
    Safe,
}

impl std::fmt::Display for HijackClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HijackClass::Missing => write!(f, "MISSING"),
            HijackClass::Phantom => write!(f, "PHANTOM"),
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
    pub source: String,
    pub details: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub import_chain: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exports: Vec<crate::pe_parser::ExportEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stealth: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stealth_notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_count: Option<usize>,
    pub is_delay_load: bool,
    pub sxs_redirected: bool,
}

pub fn resolve_dll_path(
    dll_name: &str,
    search_dirs: &[PathBuf],
    known_dlls: &HashSet<String>,
) -> Option<PathBuf> {
    let lower = dll_name.to_lowercase();
    if is_api_set(&lower) || known_dlls.contains(&lower) {
        return None;
    }
    for dir in search_dirs {
        let candidate = dir.join(&lower);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub fn get_search_dirs(app_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    dirs.push(app_dir.to_path_buf());

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

    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }

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
    lower.starts_with("api-ms-")
        || lower.starts_with("ext-ms-")
}

pub fn is_noise_dll(name: &str) -> bool {
    let lower = name.to_lowercase();
    if lower.ends_with("_hotpatch.dll") {
        return true;
    }
    if (lower.starts_with("nv") && !lower.starts_with("nvapi"))
        && (lower.contains("wgf") || lower.contains("ldumd") || lower.contains("gpucomp")
            || lower.contains("memmap") || lower.contains("spcap") || lower.contains("optimus")
            || lower.contains("cuda") || lower.contains("encode") || lower.contains("fbc"))
    {
        return true;
    }
    false
}

fn finding(
    dll_name: &str,
    class: HijackClass,
    found_path: Option<String>,
    details: String,
) -> DllFinding {
    DllFinding {
        dll_name: dll_name.to_string(),
        class,
        found_path,
        source: String::new(),
        details,
        import_chain: Vec::new(),
        exports: Vec::new(),
        stealth: None,
        stealth_notes: Vec::new(),
        export_count: None,
        is_delay_load: false,
        sxs_redirected: false,
    }
}

pub fn classify_dll(
    dll_name: &str,
    search_dirs: &[PathBuf],
    known_dlls: &HashSet<String>,
    app_dir: &Path,
) -> DllFinding {
    let lower = dll_name.to_lowercase();

    if is_api_set(&lower) {
        return finding(dll_name, HijackClass::Safe, None,
            "API set - virtual, not a real DLL".into());
    }

    if known_dlls.contains(&lower) {
        return finding(dll_name, HijackClass::KnownDll,
            Some(format!("C:\\Windows\\System32\\{lower}")),
            "Protected by KnownDLLs - always loads from System32".into());
    }

    for dir in search_dirs {
        let candidate = dir.join(&lower);
        if candidate.exists() {
            let is_app_dir = same_dir(dir, app_dir);
            let path = candidate.display().to_string();

            if is_app_dir {
                return finding(dll_name, HijackClass::Sideload, Some(path),
                    "In app dir - replace with proxy DLL".into());
            }

            return finding(dll_name, HijackClass::Phantom, Some(path),
                format!("Loaded from {} - plant proxy in app dir",
                    dir.display()));
        }
    }

    finding(dll_name, HijackClass::Missing, None,
        "Not found in any search path - drop in app dir".into())
}

pub fn classify_local(
    dll_name: &str,
    known_dlls: &HashSet<String>,
    app_dir: &Path,
) -> DllFinding {
    let lower = dll_name.to_lowercase();

    if is_api_set(&lower) {
        return finding(dll_name, HijackClass::Safe, None,
            "API set - virtual, not a real DLL".into());
    }

    if known_dlls.contains(&lower) {
        return finding(dll_name, HijackClass::KnownDll, None,
            "Protected by KnownDLLs".into());
    }

    let candidate = app_dir.join(&lower);
    if candidate.exists() {
        let path = candidate.display().to_string();
        return finding(dll_name, HijackClass::Sideload, Some(path),
            "In app dir - replace with proxy DLL".into());
    }

    finding(dll_name, HijackClass::Phantom, None,
        "Not in app dir - plant proxy here to hijack".into())
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
