use crate::search_order::{DllFinding, HijackClass};

#[derive(serde::Serialize)]
pub struct Report {
    pub target: String,
    pub app_dir: String,
    pub app_dir_writable: bool,
    pub static_imports: usize,
    pub dynamic_loads: usize,
    pub findings: Vec<DllFinding>,
}

pub fn print_table(report: &Report) {
    println!();
    println!("  DLL HIJACK HUNTER");
    println!("  ─────────────────");
    println!();
    println!("  Target:       {}", report.target);
    println!("  App dir:      {}", report.app_dir);
    println!("  App writable: {}", if report.app_dir_writable { "YES" } else { "no" });
    println!("  Static imports:  {}", report.static_imports);
    println!("  Dynamic loads:   {}", report.dynamic_loads);
    println!();

    let hijackable: Vec<&DllFinding> = report
        .findings
        .iter()
        .filter(|f| matches!(
            f.class,
            HijackClass::Missing
                | HijackClass::Phantom
                | HijackClass::WritablePath
                | HijackClass::Sideload
        ))
        .collect();

    if hijackable.is_empty() {
        println!("  No hijackable DLLs found.");
        println!();
        return;
    }

    println!(
        "  Found {} hijackable DLL{}:",
        hijackable.len(),
        if hijackable.len() == 1 { "" } else { "s" }
    );
    println!();

    // Header
    println!(
        "  {:<14} {:<30} {:<8} {}",
        "CLASS", "DLL", "SOURCE", "DETAILS"
    );
    println!(
        "  {:<14} {:<30} {:<8} {}",
        "─────", "───", "──────", "───────"
    );

    for f in &hijackable {
        let class_colored = match f.class {
            HijackClass::Missing => format!("[!] {}", f.class),
            HijackClass::Phantom => format!("[!] {}", f.class),
            HijackClass::WritablePath => format!("[*] {}", f.class),
            HijackClass::Sideload => format!("[*] {}", f.class),
            _ => format!("    {}", f.class),
        };

        println!(
            "  {:<14} {:<30} {:<8} {}",
            class_colored, f.dll_name, f.source, f.details
        );
    }
    println!();

    // Summary recommendations
    let missing_count = hijackable.iter().filter(|f| f.class == HijackClass::Missing).count();
    let phantom_count = hijackable.iter().filter(|f| f.class == HijackClass::Phantom).count();
    let writable_count = hijackable.iter().filter(|f| f.class == HijackClass::WritablePath).count();
    let sideload_count = hijackable.iter().filter(|f| f.class == HijackClass::Sideload).count();

    println!("  Summary:");
    if missing_count > 0 {
        println!("    MISSING ({missing_count}):       Drop a DLL in app dir — no original to proxy");
    }
    if phantom_count > 0 {
        println!("    PHANTOM ({phantom_count}):       Build proxy DLL — original loads from System32 but app dir is searched first");
    }
    if writable_count > 0 {
        println!("    WRITABLE_PATH ({writable_count}): Replace DLL in its writable PATH location");
    }
    if sideload_count > 0 {
        println!("    SIDELOAD ({sideload_count}):     Replace existing DLL in writable app dir with proxy");
    }
    println!();
}

pub fn print_all(report: &Report) {
    println!();
    println!("  ALL DLLs ({} total):", report.findings.len());
    println!();
    println!(
        "  {:<14} {:<30} {:<8} {}",
        "CLASS", "DLL", "SOURCE", "PATH/DETAILS"
    );
    println!(
        "  {:<14} {:<30} {:<8} {}",
        "─────", "───", "──────", "────────────"
    );

    for f in &report.findings {
        let path_or_details = f
            .found_path
            .as_deref()
            .unwrap_or(&f.details);
        println!(
            "  {:<14} {:<30} {:<8} {}",
            format!("{}", f.class),
            f.dll_name,
            f.source,
            path_or_details
        );
    }
    println!();
}

pub fn print_json(report: &Report) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("  [!] JSON serialization failed: {e}"),
    }
}
