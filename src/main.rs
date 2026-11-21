mod pe_parser;
mod debugger;
mod search_order;
mod known_dlls;
mod report;

use clap::Parser;
use search_order::{classify_dll, get_search_dirs, is_api_set, is_dir_writable, DllFinding,
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

    /// Recursive import chain depth (default: 3)
    #[arg(long, default_value = "3")]
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
    let app_dir_writable = is_dir_writable(app_dir);
    let local_mode = args.local;

    let pe_info = std::fs::read(target_path).ok()
        .and_then(|data| pe_parser::parse_info(&data).ok());

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
            let w = if is_dir_writable(dir) { " [WRITABLE]" } else { "" };
            eprintln!("       {}. {}{}", i + 1, dir.display(), w);
        }
        eprintln!();
    }

    let target_name = target_path.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Collect all DLLs via static, dynamic, and recursive chain analysis
    let mut all_dlls: HashSet<String> = HashSet::new();
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
                    for dll in imports.imports.iter().chain(imports.delay_imports.iter()) {
                        all_dlls.insert(dll.clone());
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
            search_order::classify_local(dll_name, &known_dlls, app_dir, app_dir_writable)
        } else {
            classify_dll(dll_name, &search_dirs, &known_dlls, app_dir, app_dir_writable)
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

        if args.exports && is_hijackable(&f.class) {
            if let Some(ref path) = f.found_path {
                if let Ok(dll_data) = std::fs::read(path) {
                    if let Ok(pe_exports) = pe_parser::parse_exports(&dll_data) {
                        f.exports = pe_exports.functions;
                    }
                }
            }
        }

        findings.push(f);
    }

    findings.sort_by_key(|f| match f.class {
        HijackClass::Missing => 0,
        HijackClass::Phantom => 1,
        HijackClass::WritablePath => 2,
        HijackClass::Sideload => 3,
        HijackClass::KnownDll => 4,
        HijackClass::Safe => 5,
    });

    report::Report {
        target: target_path.display().to_string(),
        app_dir: app_dir.display().to_string(),
        app_dir_writable,
        static_imports: static_count,
        dynamic_loads: dynamic_count,
        pe_info,
        findings,
    }
}

fn is_hijackable(class: &HijackClass) -> bool {
    matches!(class,
        HijackClass::Missing | HijackClass::Phantom |
        HijackClass::WritablePath | HijackClass::Sideload)
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
            app_dir_writable: r.app_dir_writable,
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
