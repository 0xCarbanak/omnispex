use crate::pe_parser::PeInfo;
use crate::search_order::{DllFinding, HijackClass};

#[derive(serde::Serialize)]
pub struct Report {
    pub target: String,
    pub app_dir: String,
    pub static_imports: usize,
    pub dynamic_loads: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe_info: Option<PeInfo>,
    pub findings: Vec<DllFinding>,
}

#[derive(serde::Serialize)]
pub struct BatchEntry {
    pub target: String,
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

    if let Some(ref info) = report.pe_info {
        println!("  Architecture: {} ({})", info.arch, info.subsystem);
        if info.is_signed {
            let signer = info.signer.as_deref().unwrap_or("unknown signer");
            println!("  Signed:       YES ({})", signer);
        } else {
            println!("  Signed:       NO");
        }
        if let Some(ref company) = info.company {
            println!("  Company:      {}", company);
        }
        if let Some(ref desc) = info.description {
            println!("  Description:  {}", desc);
        }
        if let Some(ref ver) = info.file_version {
            println!("  File version: {}", ver);
        }
        if let Some(ref product) = info.product_name {
            println!("  Product:      {}", product);
        }
        if let Some(ref orig) = info.original_filename {
            println!("  Original:     {}", orig);
        }
    }

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
        "  {:<14} {:<30} {:<8} {:<8} {}",
        "CLASS", "DLL", "SOURCE", "STEALTH", "DETAILS"
    );
    println!(
        "  {:<14} {:<30} {:<8} {:<8} {}",
        "-----", "---", "------", "-------", "-------"
    );

    for f in &hijackable {
        let grade_prefix = match f.stealth.as_deref() {
            Some("HIGH") => "[+]",
            Some("MED") => "[*]",
            _ => "[!]",
        };
        let class_colored = format!("{} {}", grade_prefix, f.class);

        let stealth_str = f.stealth.as_deref().unwrap_or("-");

        let exports_tag = if !f.exports.is_empty() {
            format!(" [{} exports]", f.exports.len())
        } else if let Some(count) = f.export_count {
            format!(" [{count} exports]")
        } else {
            String::new()
        };

        println!(
            "  {:<14} {:<30} {:<8} {:<8} {}{}",
            class_colored, f.dll_name, f.source, stealth_str, f.details, exports_tag
        );

        if f.import_chain.len() > 2 {
            println!(
                "  {:<14} chain: {}",
                "", f.import_chain.join(" -> ")
            );
        }

        let mut notes = f.stealth_notes.clone();
        if f.sxs_redirected {
            notes.retain(|n| !n.contains("SxS"));
            notes.push("SxS manifest present - test before relying on this target".into());
        }
        if !notes.is_empty() {
            println!(
                "  {:<14} stealth: {}",
                "", notes.join(", ")
            );
        }
    }
    println!();

    let missing_count = hijackable.iter().filter(|f| f.class == HijackClass::Missing).count();
    let phantom_count = hijackable.iter().filter(|f| f.class == HijackClass::Phantom).count();
    let sideload_count = hijackable.iter().filter(|f| f.class == HijackClass::Sideload).count();

    println!("  Summary:");
    if missing_count > 0 {
        println!("    MISSING ({missing_count}):       Drop a DLL in app dir - no original to proxy");
    }
    if phantom_count > 0 {
        println!("    PHANTOM ({phantom_count}):       Build proxy DLL - original loads from System32 but app dir is searched first");
    }
    if sideload_count > 0 {
        println!("    SIDELOAD ({sideload_count}):     Replace existing DLL in app dir with proxy");
    }
    println!();

    let high_count = hijackable.iter().filter(|f| f.stealth.as_deref() == Some("HIGH")).count();
    let med_count = hijackable.iter().filter(|f| f.stealth.as_deref() == Some("MED")).count();
    let low_count = hijackable.iter().filter(|f| f.stealth.as_deref() == Some("LOW")).count();

    let sxs_count = hijackable.iter().filter(|f| f.sxs_redirected).count();

    println!("  Stealth grades:");
    println!("    [+] HIGH ({high_count}):  Low export count, not EDR-monitored - easy proxy, minimal detection risk");
    println!("    [*] MED  ({med_count}):  Moderate exports or minor risk factors - workable but needs care");
    println!("    [!] LOW  ({low_count}):  Many exports, EDR-hooked, or SxS-redirected - complex proxy and/or high detection risk");
    if sxs_count > 0 {
        println!();
        println!("  [*] {sxs_count} DLL{} ha{} an SxS manifest entry.",
            if sxs_count == 1 { "" } else { "s" },
            if sxs_count == 1 { "s" } else { "ve" });
        println!("      The app manifest declares SxS dependencies that MAY cause the loader to");
        println!("      resolve from WinSxS instead of the app directory. In practice, DLL search");
        println!("      order hijacking often still works - test on target before ruling these out.");
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
