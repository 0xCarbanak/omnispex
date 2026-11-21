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

#[derive(serde::Serialize)]
pub struct BatchEntry {
    pub target: String,
    pub app_dir_writable: bool,
    pub total_imports: usize,
    pub hijackable_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_class: Option<HijackClass>,
    pub top_dlls: Vec<String>,
    pub has_deep_chain: bool,
}

#[derive(serde::Serialize)]
pub struct BatchReport {
    pub scan_dir: String,
    pub total_exes: usize,
    pub exes_with_findings: usize,
    pub entries: Vec<BatchEntry>,
}

pub fn print_table(report: &Report) {
    println!();
    println!("  OMNISPEX");
    println!("  --------");
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

    println!(
        "  {:<14} {:<30} {:<8} {}",
        "CLASS", "DLL", "SOURCE", "DETAILS"
    );
    println!(
        "  {:<14} {:<30} {:<8} {}",
        "-----", "---", "------", "-------"
    );

    for f in &hijackable {
        let class_colored = match f.class {
            HijackClass::Missing => format!("[!] {}", f.class),
            HijackClass::Phantom => format!("[!] {}", f.class),
            HijackClass::WritablePath => format!("[*] {}", f.class),
            HijackClass::Sideload => format!("[*] {}", f.class),
            _ => format!("    {}", f.class),
        };

        let exports_tag = if !f.exports.is_empty() {
            format!(" [{} exports]", f.exports.len())
        } else {
            String::new()
        };

        println!(
            "  {:<14} {:<30} {:<8} {}{}",
            class_colored, f.dll_name, f.source, f.details, exports_tag
        );

        if f.import_chain.len() > 2 {
            println!(
                "  {:<14} chain: {}",
                "", f.import_chain.join(" -> ")
            );
        }
    }
    println!();

    let missing_count = hijackable.iter().filter(|f| f.class == HijackClass::Missing).count();
    let phantom_count = hijackable.iter().filter(|f| f.class == HijackClass::Phantom).count();
    let writable_count = hijackable.iter().filter(|f| f.class == HijackClass::WritablePath).count();
    let sideload_count = hijackable.iter().filter(|f| f.class == HijackClass::Sideload).count();

    println!("  Summary:");
    if missing_count > 0 {
        println!("    MISSING ({missing_count}):       Drop a DLL in app dir - no original to proxy");
    }
    if phantom_count > 0 {
        println!("    PHANTOM ({phantom_count}):       Build proxy DLL - original loads from System32 but app dir is searched first");
    }
    if writable_count > 0 {
        println!("    WRITABLE_PATH ({writable_count}): Replace DLL in its writable PATH location");
    }
    if sideload_count > 0 {
        println!("    SIDELOAD ({sideload_count}):     Replace existing DLL in writable app dir with proxy");
    }
    println!();

    // Print exports section if any findings have exports
    let with_exports: Vec<&&DllFinding> = hijackable.iter()
        .filter(|f| !f.exports.is_empty())
        .collect();
    if !with_exports.is_empty() {
        println!("  Exports (for proxy DLL generation):");
        println!("  -----------------------------------");
        for f in with_exports {
            let ordinal_only = f.exports.iter()
                .filter(|e| e.name.is_none())
                .count();
            let forwarded = f.exports.iter()
                .filter(|e| e.forward.is_some())
                .count();

            println!();
            println!("  {} ({} exports, {} by ordinal only, {} forwarded):",
                f.dll_name, f.exports.len(), ordinal_only, forwarded);

            for exp in &f.exports {
                let name_str = exp.name.as_deref().unwrap_or("(ordinal only)");
                let fwd_str = exp.forward.as_ref()
                    .map(|fw| format!(" -> {fw}"))
                    .unwrap_or_default();
                println!("    @{:<5} {}{}", exp.ordinal, name_str, fwd_str);
            }
        }
        println!();
    }
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
        "-----", "---", "------", "------------"
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
        if f.import_chain.len() > 2 {
            println!(
                "  {:<14} chain: {}",
                "", f.import_chain.join(" -> ")
            );
        }
    }
    println!();
}

pub fn print_json(report: &Report) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("  [!] JSON serialization failed: {e}"),
    }
}

pub fn print_batch_table(report: &BatchReport) {
    println!();
    println!("  OMNISPEX - BATCH SCAN");
    println!("  ---------------------");
    println!();
    println!("  Scan dir:           {}", report.scan_dir);
    println!("  Total executables:  {}", report.total_exes);
    println!("  With findings:      {}", report.exes_with_findings);
    println!();

    if report.entries.is_empty() {
        println!("  No hijackable DLLs found in any executable.");
        println!();
        return;
    }

    println!(
        "  {:<5} {:<14} {:<5} {:<5} {}",
        "RANK", "BEST CLASS", "HITS", "CHAIN", "TARGET"
    );
    println!(
        "  {:<5} {:<14} {:<5} {:<5} {}",
        "----", "----------", "----", "-----", "------"
    );

    for (i, entry) in report.entries.iter().enumerate() {
        let class_str = entry.best_class.as_ref()
            .map(|c| format!("{c}"))
            .unwrap_or_else(|| "-".into());
        let chain_marker = if entry.has_deep_chain { "yes" } else { "" };

        println!(
            "  {:<5} {:<14} {:<5} {:<5} {}",
            i + 1,
            class_str,
            entry.hijackable_count,
            chain_marker,
            entry.target,
        );

        for dll in &entry.top_dlls {
            println!("  {:<5} {:<14}       {}", "", "", dll);
        }
    }
    println!();
}

pub fn print_batch_json(report: &BatchReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("  [!] JSON serialization failed: {e}"),
    }
}
