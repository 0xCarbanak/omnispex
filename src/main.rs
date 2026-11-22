mod pe_parser;
mod debugger;
mod search_order;
mod known_dlls;
mod report;

use clap::Parser;
use search_order::{classify_dll, get_search_dirs, is_api_set, DllFinding,
    HijackClass, resolve_dll_path};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "omnispex",
    about = "Reveal DLL hijacking opportunities in Windows executables"
)]
struct Args {
    /// Target executable to analyze (optional if --scan-dir is used)
    target: Option<String>,

    /// Scan all EXEs in a directory recursively (static-only, no dynamic)
    #[arg(long)]
    scan_dir: Option<String>,

    /// OPSEC-safe: only read the PE file + check the app directory
    #[arg(long)]
    local: bool,

    /// Only parse PE imports (no execution)
    #[arg(long)]
    static_only: bool,

    /// Only run dynamic debug session
    #[arg(long)]
    dynamic_only: bool,

    /// Recursive import chain depth (default: 1 = direct imports only)
    #[arg(long, default_value = "1")]
    depth: usize,

    /// Show exports of hijackable DLLs (needed for proxy DLL generation)
    #[arg(long)]
    exports: bool,

    /// Dynamic analysis timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Arguments to pass to target during dynamic analysis
    #[arg(long)]
    args: Option<String>,

    /// Output JSON instead of table
    #[arg(long)]
    json: bool,

    /// Show all DLLs including non-hijackable
    #[arg(long)]
    show_all: bool,

    /// Show search order details per DLL
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    if args.scan_dir.is_some() {
        run_batch(&args);
    } else if let Some(ref target) = args.target {
        run_single(target, &args);
    } else {
        eprintln!("  [!] Provide a target EXE or --scan-dir <path>");
        std::process::exit(1);
    }
}

fn run_single(target: &str, args: &Args) {
    let target_path = Path::new(target);
    if !target_path.exists() {
        eprintln!("  [!] Target not found: {target}");
        std::process::exit(1);
    }

    let target_path = match target_path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  [!] Can't resolve path: {e}");
            std::process::exit(1);
        }
    };

    // If the target is a directory, find .exe files inside it
    let target_path = if target_path.is_dir() {
        match find_exe_in_dir(&target_path) {
            Some(exe) => exe,
            None => {
                eprintln!("  [!] No .exe files found in: {}", target_path.display());
                std::process::exit(1);
            }
        }
    } else {
        target_path
    };

    let r = analyze_target(&target_path, args);

    if args.json {
        report::print_json(&r);
    } else {
        report::print_table(&r);
        if args.show_all {
            report::print_all(&r);
        }
    }
}

fn analyze_target(target_path: &Path, args: &Args) -> report::Report {
    let app_dir = target_path.parent().unwrap_or(Path::new("."));
    let local_mode = args.local;

    let target_data = std::fs::read(target_path).ok();
    let pe_info = target_data.as_ref()
        .and_then(|data| pe_parser::parse_info(data).ok());

    let manifest = target_data.as_ref()
        .and_then(|data| pe_parser::parse_manifest(data));
    let sxs_dlls = manifest.as_ref()
        .map(|m| pe_parser::sxs_redirected_dlls(m))
        .unwrap_or_default();

    let mut known_dlls = known_dlls::load_known_dlls();
    known_dlls.extend(known_dlls::loader_critical_dlls());

    let search_dirs = if local_mode {
        vec![app_dir.to_path_buf()]
    } else {
        get_search_dirs(app_dir)
    };

    if args.verbose {
        if local_mode {
            eprintln!("  [*] Local mode - only checking app directory");
        }
        eprintln!("  [*] Search order:");
        for (i, dir) in search_dirs.iter().enumerate() {
            eprintln!("       {}. {}", i + 1, dir.display());
        }
        eprintln!();
    }

    let target_name = target_path.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Collect all DLLs via static, dynamic, and recursive chain analysis
    let mut all_dlls: HashSet<String> = HashSet::new();
    let mut delay_load_dlls: HashSet<String> = HashSet::new();
    let mut static_count = 0usize;
    let mut dynamic_count = 0usize;
    let mut dynamic_paths: HashMap<String, String> = HashMap::new();
    // chains: dll_name -> shortest chain from the target EXE
    let mut chains: HashMap<String, Vec<String>> = HashMap::new();

    // Static analysis
    if !args.dynamic_only || local_mode {
        match std::fs::read(target_path) {
            Ok(data) => match pe_parser::parse_imports(&data) {
                Ok(imports) => {
                    static_count = imports.imports.len() + imports.delay_imports.len();
                    if args.verbose {
                        eprintln!(
                            "  [*] Static: {} imports, {} delay imports",
                            imports.imports.len(), imports.delay_imports.len()
                        );
                    }
                    for dll in &imports.imports {
                        all_dlls.insert(dll.clone());
                        chains.insert(dll.clone(), vec![target_name.clone(), dll.clone()]);
                    }
                    for dll in &imports.delay_imports {
                        all_dlls.insert(dll.clone());
                        delay_load_dlls.insert(dll.clone());
                        chains.insert(dll.clone(), vec![target_name.clone(), dll.clone()]);
                    }

                    // Recursive import chain (BFS)
                    if args.depth > 1 {
                        let direct: Vec<String> = imports.imports.iter()
                            .chain(imports.delay_imports.iter())
                            .cloned().collect();
                        walk_import_chain(
                            &direct,
                            &target_name,
                            &search_dirs,
                            &known_dlls,
                            args.depth,
                            args.verbose,
                            &mut all_dlls,
                            &mut chains,
                        );
                    }
                }
                Err(e) => eprintln!("  [!] PE parse error: {e}"),
            },
            Err(e) => eprintln!("  [!] Can't read target: {e}"),
        }
    }

    // Dynamic analysis
    if !args.static_only && !local_mode {
        if args.verbose {
            eprintln!("  [*] Launching dynamic analysis (timeout: {}s)...", args.timeout);
        }
        match debugger::run_debug_session(
            target_path.to_str().unwrap_or(""),
            args.args.as_deref(),
            args.timeout,
        ) {
            Ok(loaded) => {
                dynamic_count = loaded.len();
                if args.verbose {
                    eprintln!("  [*] Dynamic: {} DLLs loaded", loaded.len());
                }
                for path in loaded {
                    let name = Path::new(&path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    if !name.is_empty() {
                        dynamic_paths.insert(name.clone(), path);
                        all_dlls.insert(name);
                    }
                }
            }
            Err(e) => {
                if args.dynamic_only {
                    eprintln!("  [!] Dynamic analysis failed: {e}");
                    std::process::exit(1);
                } else {
                    eprintln!("  [*] Dynamic analysis skipped: {e}");
                }
            }
        }
    }

    // Classify each DLL
    let mut findings: Vec<DllFinding> = Vec::new();

    for dll_name in &all_dlls {
        if is_api_set(dll_name) && !args.show_all {
            continue;
        }

        let mut f = if local_mode {
            search_order::classify_local(dll_name, &known_dlls, app_dir)
        } else {
            classify_dll(dll_name, &search_dirs, &known_dlls, app_dir)
        };

        let in_static = !args.dynamic_only || local_mode;
        let in_dynamic = dynamic_paths.contains_key(dll_name);
        f.source = match (in_static, in_dynamic) {
            (true, true) => "both".into(),
            (true, false) => "static".into(),
            (false, true) => "dynamic".into(),
            _ => "".into(),
        };

        if let Some(path) = dynamic_paths.get(dll_name) {
            if f.found_path.is_none() {
                f.found_path = Some(path.clone());
            }
        }

        if let Some(chain) = chains.get(dll_name) {
            if chain.len() > 2 {
                f.import_chain = chain.clone();
            }
        }

        if is_hijackable(&f.class) {
            f.is_delay_load = delay_load_dlls.contains(dll_name);
            f.sxs_redirected = sxs_dlls.contains(&dll_name.to_lowercase());

            // Resolve the DLL file to read exports from.
            // For PHANTOM in --local mode, found_path is None because we only
            // check the app dir. Fall back to System32.
            let dll_file = f.found_path.clone().or_else(|| {
                if f.class == HijackClass::Phantom || f.class == HijackClass::Missing {
                    let sys32 = PathBuf::from("C:\\Windows\\System32").join(dll_name);
                    if sys32.exists() { Some(sys32.display().to_string()) } else { None }
                } else {
                    None
                }
            });

            if let Some(ref path) = dll_file {
                if let Ok(dll_data) = std::fs::read(path) {
                    if args.exports {
                        if let Ok(pe_exports) = pe_parser::parse_exports(&dll_data) {
                            f.export_count = Some(pe_exports.functions.len());
                            f.exports = pe_exports.functions;
                        }
                    } else if let Ok(count) = pe_parser::count_exports(&dll_data) {
                        f.export_count = Some(count);
                    }
                }
            }

            compute_stealth(&mut f);
        }

        findings.push(f);
    }

    findings.sort_by(|a, b| {
        let class_ord = |c: &HijackClass| match c {
            HijackClass::Missing => 0,
            HijackClass::Phantom => 1,
            HijackClass::Sideload => 2,
            HijackClass::KnownDll => 3,
            HijackClass::Safe => 4,
        };
        let stealth_ord = |s: &Option<String>| match s.as_deref() {
            Some("HIGH") => 0,
            Some("MED") => 1,
            Some("LOW") => 2,
            _ => 3,
        };
        class_ord(&a.class).cmp(&class_ord(&b.class))
            .then(stealth_ord(&a.stealth).cmp(&stealth_ord(&b.stealth)))
    });

    report::Report {
        target: target_path.display().to_string(),
        app_dir: app_dir.display().to_string(),
        static_imports: static_count,
        dynamic_loads: dynamic_count,
        pe_info,
        findings,
    }
}

const EDR_WATCHED: &[&str] = &[
    "amsi.dll", "crypt32.dll", "wintrust.dll", "bcrypt.dll", "ncrypt.dll",
    "wininet.dll", "winhttp.dll", "urlmon.dll", "dbghelp.dll", "dbgcore.dll",
    "clr.dll", "mscoree.dll", "mscorlib.dll", "ws2_32.dll", "dnsapi.dll",
    "secur32.dll", "sspicli.dll", "schannel.dll", "crypt32.dll",
];

fn compute_stealth(f: &mut DllFinding) {
    let mut score: i32 = 50;
    let mut notes: Vec<String> = Vec::new();
    let lower = f.dll_name.to_lowercase();

    // Export count scoring
    match f.export_count {
        Some(n) if n <= 5 => {
            score += 20;
            notes.push(format!("{n} exports (trivial proxy)"));
        }
        Some(n) if n <= 20 => {
            score += 10;
            notes.push(format!("{n} exports"));
        }
        Some(n) if n <= 50 => {
            notes.push(format!("{n} exports"));
        }
        Some(n) if n <= 150 => {
            score -= 10;
            notes.push(format!("{n} exports (complex proxy)"));
        }
        Some(n) => {
            score -= 25;
            notes.push(format!("{n} exports (massive proxy)"));
        }
        None => {
            notes.push("export count unknown".into());
        }
    }

    // Delay-load bonus
    if f.is_delay_load {
        score += 10;
        notes.push("delay-load".into());
    }

    // EDR-watched penalty
    if EDR_WATCHED.contains(&lower.as_str()) {
        score -= 30;
        notes.push("EDR-watched".into());
    }

    // SxS manifest redirect — DLL loads from WinSxS, not app dir
    if f.sxs_redirected {
        score -= 40;
        notes.push("SxS-redirected (manifest overrides search order)".into());
    }

    // Chain depth — direct imports are simpler to exploit
    let depth = if f.import_chain.len() > 2 { f.import_chain.len() - 1 } else { 1 };
    match depth {
        1 => {
            score += 5;
            notes.push("direct import".into());
        }
        2 => {
            notes.push("depth-2 chain".into());
        }
        _ => {
            score -= 5;
            notes.push(format!("depth-{depth} chain"));
        }
    }

    // Class bonus
    match f.class {
        HijackClass::Missing => {
            score += 10;
            notes.push("no original needed".into());
        }
        HijackClass::Phantom => {
            score += 5;
        }
        _ => {}
    }

    let grade = if score >= 65 { "HIGH" } else if score >= 40 { "MED" } else { "LOW" };

    f.stealth = Some(grade.to_string());
    f.stealth_notes = notes;
}

fn is_hijackable(class: &HijackClass) -> bool {
    matches!(class,
        HijackClass::Missing | HijackClass::Phantom |
        HijackClass::Sideload)
}

fn walk_import_chain(
    direct_imports: &[String],
    target_name: &str,
    search_dirs: &[PathBuf],
    known_dlls: &HashSet<String>,
    max_depth: usize,
    verbose: bool,
    all_dlls: &mut HashSet<String>,
    chains: &mut HashMap<String, Vec<String>>,
) {
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(target_name.to_lowercase());

    // BFS queue: (dll_name, depth, parent_chain)
    let mut queue: VecDeque<(String, usize, Vec<String>)> = VecDeque::new();

    for dll in direct_imports {
        let lower = dll.to_lowercase();
        visited.insert(lower.clone());
        queue.push_back((lower, 2, vec![target_name.to_string(), dll.clone()]));
    }

    let mut recursive_count = 0usize;

    while let Some((dll_name, depth, parent_chain)) = queue.pop_front() {
        if depth > max_depth {
            continue;
        }

        let Some(dll_path) = resolve_dll_path(&dll_name, search_dirs, known_dlls) else {
            continue;
        };

        let data = match std::fs::read(&dll_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let imports = match pe_parser::parse_imports(&data) {
            Ok(i) => i,
            Err(_) => continue,
        };

        for child in imports.imports.iter().chain(imports.delay_imports.iter()) {
            let child_lower = child.to_lowercase();
            if visited.contains(&child_lower) {
                continue;
            }
            visited.insert(child_lower.clone());

            let mut chain = parent_chain.clone();
            chain.push(child_lower.clone());

            all_dlls.insert(child_lower.clone());
            chains.entry(child_lower.clone()).or_insert_with(|| chain.clone());
            recursive_count += 1;

            queue.push_back((child_lower, depth + 1, chain));
        }
    }

    if verbose && recursive_count > 0 {
        eprintln!("  [*] Recursive: {} additional DLLs from import chains (depth {})",
            recursive_count, max_depth);
    }
}

fn run_batch(args: &Args) {
    let scan_dir = args.scan_dir.as_deref().unwrap();
    let scan_path = Path::new(scan_dir);

    if !scan_path.exists() || !scan_path.is_dir() {
        eprintln!("  [!] Not a directory: {scan_dir}");
        std::process::exit(1);
    }

    eprintln!("  [*] Scanning {} for executables...", scan_dir);
    let exes = find_exes(scan_path);
    eprintln!("  [*] Found {} executables", exes.len());

    if exes.is_empty() {
        return;
    }

    // Force static-only for batch mode
    let batch_args = Args {
        target: None,
        scan_dir: None,
        local: args.local,
        static_only: true,
        dynamic_only: false,
        depth: args.depth,
        exports: false,
        timeout: 0,
        args: None,
        json: args.json,
        show_all: args.show_all,
        verbose: false,
    };

    let mut summaries: Vec<report::BatchEntry> = Vec::new();

    for (i, exe) in exes.iter().enumerate() {
        if !args.json {
            eprint!("  [{}/{}] {}\r", i + 1, exes.len(), exe.display());
        }

        let r = analyze_target(exe, &batch_args);

        let hijackable: Vec<&DllFinding> = r.findings.iter()
            .filter(|f| is_hijackable(&f.class))
            .collect();

        if hijackable.is_empty() && !args.show_all {
            continue;
        }

        let best_class = hijackable.first().map(|f| f.class.clone());
        let top_dlls: Vec<String> = hijackable.iter()
            .take(5)
            .map(|f| format!("{} ({})", f.dll_name, f.class))
            .collect();
        let has_chain = hijackable.iter().any(|f| f.import_chain.len() > 2);

        summaries.push(report::BatchEntry {
            target: exe.display().to_string(),
            total_imports: r.static_imports,
            hijackable_count: hijackable.len(),
            best_class,
            top_dlls,
            has_deep_chain: has_chain,
        });
    }

    summaries.sort_by(|a, b| b.hijackable_count.cmp(&a.hijackable_count));

    let batch = report::BatchReport {
        scan_dir: scan_dir.to_string(),
        total_exes: exes.len(),
        exes_with_findings: summaries.len(),
        entries: summaries,
    };

    if args.json {
        report::print_batch_json(&batch);
    } else {
        eprintln!();
        report::print_batch_table(&batch);
    }
}

/// When the user points at a directory instead of an .exe, find the right
/// executable inside it.  Rules:
///   1. Collect all .exe files in the top level of the directory (not recursive).
///   2. If exactly one, use it.
///   3. If multiple, prefer the one whose stem matches the directory name
///      (e.g. `notepad++.exe` inside `npp.8.6.8.portable.x64/` won't match,
///       but `npp.exe` inside `npp/` would).
///   4. Failing that, pick the largest .exe (most likely the main application).
fn find_exe_in_dir(dir: &Path) -> Option<PathBuf> {
    let entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .map(|ext| ext.to_string_lossy().to_lowercase() == "exe")
                        .unwrap_or(false)
            })
            .collect(),
        Err(_) => return None,
    };

    if entries.is_empty() {
        return None;
    }

    if entries.len() == 1 {
        eprintln!("  [*] Directory target - found: {}", entries[0].display());
        return Some(entries[0].clone());
    }

    // Multiple .exe files - try to match directory name
    let dir_stem = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if !dir_stem.is_empty() {
        for exe in &entries {
            let exe_stem = exe
                .file_stem()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if exe_stem == dir_stem {
                eprintln!(
                    "  [*] Directory target ({} .exe files) - matched by name: {}",
                    entries.len(),
                    exe.display()
                );
                return Some(exe.clone());
            }
        }
    }

    // No name match - pick the largest .exe
    let largest = entries
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| (p, m.len())))
        .max_by_key(|(_, size)| *size)
        .map(|(p, _)| p.clone());

    if let Some(ref exe) = largest {
        eprintln!(
            "  [*] Directory target ({} .exe files) - selected largest: {}",
            entries.len(),
            exe.display()
        );

        // List the other options so the user knows
        eprintln!("       Other .exe files in directory:");
        for e in &entries {
            if e != exe {
                let size = std::fs::metadata(e)
                    .map(|m| m.len())
                    .unwrap_or(0);
                eprintln!("         {} ({} bytes)", e.display(), size);
            }
        }
    }

    largest
}

fn find_exes(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    find_exes_recursive(dir, &mut result, 0);
    result
}

fn find_exes_recursive(dir: &Path, result: &mut Vec<PathBuf>, depth: usize) {
    if depth > 10 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            find_exes_recursive(&path, result, depth + 1);
        } else if let Some(ext) = path.extension() {
            if ext.to_string_lossy().to_lowercase() == "exe" {
                result.push(path);
            }
        }
    }
}
