mod pe_parser;
mod debugger;
mod search_order;
mod known_dlls;
mod report;

use clap::Parser;
use search_order::{classify_dll, get_search_dirs, is_api_set, is_dir_writable, DllFinding};
use std::collections::HashSet;
use std::path::Path;

#[derive(Parser)]
#[command(
    name = "dll-hijack-hunter",
    about = "Discover DLL hijacking opportunities for a target executable"
)]
struct Args {
    /// Target executable to analyze
    target: String,

    /// OPSEC-safe: only read the PE file + check the app directory. No process
    /// launch, no System32/PATH probing, no writability checks outside app dir.
    #[arg(long)]
    local: bool,

    /// Only parse PE imports (no execution)
    #[arg(long)]
    static_only: bool,

    /// Only run dynamic debug session
    #[arg(long)]
    dynamic_only: bool,

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

    let target_path = Path::new(&args.target);
    if !target_path.exists() {
        eprintln!("  [!] Target not found: {}", args.target);
        std::process::exit(1);
    }

    let target_path = match target_path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  [!] Can't resolve path: {e}");
            std::process::exit(1);
        }
    };

    let app_dir = target_path.parent().unwrap_or(Path::new("."));
    let app_dir_writable = is_dir_writable(app_dir);
    let local_mode = args.local;

    let mut known_dlls = known_dlls::load_known_dlls();
    known_dlls.extend(known_dlls::loader_critical_dlls());

    let search_dirs = if local_mode {
        vec![app_dir.to_path_buf()]
    } else {
        get_search_dirs(app_dir)
    };

    if args.verbose {
        if local_mode {
            eprintln!("  [*] Local mode — only checking app directory");
        }
        eprintln!("  [*] Search order:");
        for (i, dir) in search_dirs.iter().enumerate() {
            let w = if is_dir_writable(dir) { " [WRITABLE]" } else { "" };
            eprintln!("       {}. {}{}", i + 1, dir.display(), w);
        }
        eprintln!();
    }

    let mut all_dlls: HashSet<String> = HashSet::new();
    let mut static_count = 0usize;
    let mut dynamic_count = 0usize;
    let mut dynamic_paths: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Static analysis — always runs in local mode, respects --dynamic-only otherwise
    if !args.dynamic_only || local_mode {
        match std::fs::read(&target_path) {
            Ok(data) => match pe_parser::parse_imports(&data) {
                Ok(imports) => {
                    static_count = imports.imports.len() + imports.delay_imports.len();
                    if args.verbose {
                        eprintln!(
                            "  [*] Static: {} imports, {} delay imports",
                            imports.imports.len(),
                            imports.delay_imports.len()
                        );
                    }
                    for dll in imports.imports {
                        all_dlls.insert(dll);
                    }
                    for dll in imports.delay_imports {
                        all_dlls.insert(dll);
                    }
                }
                Err(e) => eprintln!("  [!] PE parse error: {e}"),
            },
            Err(e) => eprintln!("  [!] Can't read target: {e}"),
        }
    }

    // Dynamic analysis — never runs in local mode
    if !args.static_only && !local_mode {
        if args.verbose {
            eprintln!("  [*] Launching dynamic analysis (timeout: {}s)...", args.timeout);
        }
        match debugger::run_debug_session(
            target_path.to_str().unwrap_or(&args.target),
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
                if !args.dynamic_only {
                    eprintln!("  [*] Dynamic analysis skipped: {e}");
                } else {
                    eprintln!("  [!] Dynamic analysis failed: {e}");
                    std::process::exit(1);
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

        let mut finding = if local_mode {
            search_order::classify_local(dll_name, &known_dlls, app_dir, app_dir_writable)
        } else {
            classify_dll(dll_name, &search_dirs, &known_dlls, app_dir, app_dir_writable)
        };

        // Tag source (static/dynamic/both)
        let in_static = !args.dynamic_only || local_mode;
        let in_dynamic = dynamic_paths.contains_key(dll_name);
        finding.source = match (in_static, in_dynamic) {
            (true, true) => "both".into(),
            (true, false) => "static".into(),
            (false, true) => "dynamic".into(),
            _ => "".into(),
        };

        // If we have a dynamic path, use it
        if let Some(path) = dynamic_paths.get(dll_name) {
            if finding.found_path.is_none() {
                finding.found_path = Some(path.clone());
            }
        }

        findings.push(finding);
    }

    // Sort: hijackable first (Missing > Phantom > WritablePath > Sideload > KnownDll > Safe)
    findings.sort_by_key(|f| match f.class {
        search_order::HijackClass::Missing => 0,
        search_order::HijackClass::Phantom => 1,
        search_order::HijackClass::WritablePath => 2,
        search_order::HijackClass::Sideload => 3,
        search_order::HijackClass::KnownDll => 4,
        search_order::HijackClass::Safe => 5,
    });

    let r = report::Report {
        target: target_path.display().to_string(),
        app_dir: app_dir.display().to_string(),
        app_dir_writable,
        static_imports: static_count,
        dynamic_loads: dynamic_count,
        findings,
    };

    if args.json {
        report::print_json(&r);
    } else {
        report::print_table(&r);
        if args.show_all {
            report::print_all(&r);
        }
    }
}
