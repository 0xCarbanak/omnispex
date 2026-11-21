# DLL Hijack Hunter

Discovers DLL search order hijacking opportunities in Windows executables. Parses PE imports, walks the DLL search order, checks directory permissions, and follows recursive import chains to surface every hijackable DLL -- direct or transitive.

**This is an offline research tool.** You run it on your own machine against a copy of the target application, then use the findings to build your payload.

## Quick Start

```
dll-hijack-hunter.exe C:\Temp\npp\notepad++.exe --local
```

```
  DLL HIJACK HUNTER
  -----------------

  Target:       C:\Temp\npp\notepad++.exe
  App dir:      C:\Temp\npp
  App writable: YES
  Static imports:  19

  Found 12 hijackable DLLs:

  CLASS          DLL                            SOURCE   DETAILS
  -----          ---                            ------   -------
  [!] PHANTOM    dwmapi.dll                     static   Not in app dir - plant here to hijack
  [!] PHANTOM    wintrust.dll                   static   Not in app dir - plant here to hijack
  [!] PHANTOM    userenv.dll                    static   Not in app dir - plant here to hijack
                 chain: notepad++.exe -> version.dll -> userenv.dll
  [*] SIDELOAD   version.dll                    static   Present in writable app dir - replace with proxy DLL
```

## How It Works

1. Parse static imports and delay-load imports from the PE header
2. Optionally launch the target under the Debug API to capture runtime `LoadLibrary` calls
3. For each DLL, walk the Windows DLL search order and check directory writability
4. Follow import chains recursively (BFS) to find transitive dependencies
5. Classify each DLL by hijack potential

### Classifications

| Class | Meaning | Attack |
|-------|---------|--------|
| `MISSING` | Not found anywhere in search path | Drop your DLL in app directory |
| `PHANTOM` | Loaded from System32, but app dir is searched first and writable | Plant proxy DLL in app dir |
| `WRITABLE_PATH` | Loaded from a writable PATH directory | Replace DLL in that directory |
| `SIDELOAD` | Already in app dir, directory is writable | Replace with proxy DLL |
| `KNOWN_DLL` | Protected by KnownDLLs registry | Not hijackable |
| `SAFE` | Not exploitable (non-writable location, API set, etc.) | -- |

Automatically filtered: KnownDLLs (from registry), loader-critical DLLs (ntdll, kernelbase, etc.), API sets (api-ms-win-*, ext-ms-win-*).

## Usage

```
dll-hijack-hunter.exe [target.exe] [options]
```

### Modes

| Mode | Flag | What it does |
|------|------|-------------|
| Local | `--local` | PE + app dir only. Fast, no process launch, OPSEC-safe |
| Static | `--static-only` | PE + full DLL search order walk, no execution |
| Full | *(default)* | Static + dynamic (launches process under debugger) |
| Batch | `--scan-dir <path>` | Scan all EXEs in a directory, rank by hijackable count |

### Options

| Flag | Description |
|------|-------------|
| `--local` | Only check app directory (no search order walk, no process launch) |
| `--static-only` | Parse PE imports + walk search order, no execution |
| `--dynamic-only` | Only run debug session |
| `--scan-dir <path>` | Batch scan: find all EXEs recursively, rank results |
| `--depth <N>` | Recursive import chain depth (default: 3) |
| `--timeout <secs>` | Dynamic analysis timeout (default: 30) |
| `--args <str>` | Arguments to pass to target during dynamic analysis |
| `--json` | Output JSON instead of table |
| `--show-all` | Include non-hijackable DLLs in output |
| `-v, --verbose` | Show search order, chain walk progress, per-module details |

### Examples

Local check (fast, reads PE + app dir only):
```
dll-hijack-hunter.exe C:\Temp\npp\notepad++.exe --local
```

Full analysis with dynamic tracing:
```
dll-hijack-hunter.exe C:\Temp\npp\notepad++.exe --timeout 15
```

Deep import chain walk (5 levels):
```
dll-hijack-hunter.exe C:\Temp\npp\notepad++.exe --local --depth 5 -v
```

Batch scan an entire program directory:
```
dll-hijack-hunter.exe --scan-dir "C:\Program Files\SomeVendor" --local
```

JSON for scripting:
```
dll-hijack-hunter.exe C:\Temp\npp\notepad++.exe --local --json
```

## Batch Scan

`--scan-dir` recursively finds all `.exe` files (up to 10 levels deep), runs static analysis on each, and outputs a ranked table:

```
  DLL HIJACK HUNTER - BATCH SCAN
  ------------------------------

  Scan dir:           C:\Temp\npp
  Total executables:  2
  With findings:      2

  RANK  BEST CLASS     HITS  CHAIN TARGET
  ----  ----------     ----  ----- ------
  1     PHANTOM        12    yes   C:\Temp\npp\notepad++.exe
                             crypt32.dll (PHANTOM)
                             wintrust.dll (PHANTOM)
                             comctl32.dll (PHANTOM)
                             bcrypt.dll (PHANTOM)
                             dwmapi.dll (PHANTOM)
  2     PHANTOM        4     yes   C:\Temp\npp\updater\GUP.exe
                             bcrypt.dll (PHANTOM)
                             crypt32.dll (PHANTOM)
                             comctl32.dll (PHANTOM)
                             libcurl.dll (SIDELOAD)
```

Sorts by hijackable count descending, shows the top 5 DLLs per target. Use this to quickly triage which applications in an environment have the most hijacking surface.

## Recursive Import Chains

`--depth` controls how deep the tool follows DLL dependencies beyond the target's direct imports. The default depth of 3 catches most practical chains.

At depth 1, only the EXE's own imports are checked. At higher depths, the tool reads the PE of each resolved DLL and walks its imports too, using BFS to find the shortest path from the EXE to each discovered DLL:

```
  [!] PHANTOM    userenv.dll                    static   Not in app dir - plant here to hijack
                 chain: notepad++.exe -> version.dll -> userenv.dll
  [!] PHANTOM    bcrypt.dll                     static   Not in app dir - plant here to hijack
                 chain: notepad++.exe -> version.dll -> bcrypt.dll
```

This surfaces DLLs that aren't direct imports of the target but are loaded transitively through its dependencies. A PHANTOM DLL three levels deep is still plantable in the app directory if it's writable.

Only DLLs resolvable on disk are followed -- KnownDLLs and API sets are skipped since they can't be hijacked and the OS doesn't load them from the filesystem search path.

## DLL Search Order

The tool walks the standard Windows search order (SafeDllSearchMode enabled):

1. Application directory
2. System directory (System32)
3. Windows directory
4. Current working directory
5. PATH directories

For each DLL, it finds the first directory in this order where the DLL exists, checks if the application directory (searched first) is writable, and classifies accordingly.

## Building

Cross-compile from Linux:
```bash
cargo build --release --target x86_64-pc-windows-gnu
```

Build on Windows:
```
cargo build --release
```

Output: ~535KB standalone executable, no runtime dependencies.

## Architecture

```
src/
  main.rs           CLI, orchestration, BFS import chain walker, batch scanner
  pe_parser.rs      PE import table + delay-load parsing
  debugger.rs       Dynamic analysis via CreateProcessW + DEBUG_PROCESS
  search_order.rs   DLL search order walk, writability checks, classification
  known_dlls.rs     KnownDLLs registry + loader-critical DLL filtering
  report.rs         Table, JSON, and batch output formatting
```

**Static analysis** reads the PE import table and delay-load directory directly from the binary. Finds all DLLs declared as dependencies without executing anything.

**Dynamic analysis** launches the target under `DEBUG_PROCESS` and captures `LOAD_DLL_DEBUG_EVENT` messages. Catches DLLs loaded at runtime via `LoadLibrary` -- plugins, COM objects, delay-loaded dependencies, etc. The process is terminated after the timeout.

Combined mode runs both and merges results, tagging each finding with its source (`static`, `dynamic`, or `both`).
