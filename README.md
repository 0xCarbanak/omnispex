# Omnispex

<img width="1672" height="941" alt="16e55700-1b1c-4050-bcbc-4d1a9d0c76ac" src="https://github.com/user-attachments/assets/2d95e066-74c6-48c1-b5cf-2887b7132c5d" />

> *"Should it be kept focussed for an extended period of time, an Omnispex will determine the weak points of those it scrutinises and pass them on to its master."*

DLL search order hijacking scanner for Windows executables. Parses PE imports, walks the DLL search order, follows recursive import chains, enumerates exports, and grades each target by stealth -- everything you need to find and build proxy DLL hijacks.

**This is an offline research tool.** Run it on your own machine against a copy of the target application, then use the findings to build your payload.

## Quick Start

```
omnispex.exe C:\Temp\npp\notepad++.exe --local --exports
```

```
  OMNISPEX
  --------

  Target:       C:\Temp\npp\notepad++.exe
  App dir:      C:\Temp\npp
  Architecture: x64 (GUI)
  Signed:       YES (Notepad++)
  Company:      Don HO don.h@free.fr
  Description:  Notepad++
  File version: 8.6.8
  Product:      Notepad++
  Original:     notepad++.exe
  Static imports:  19

  Found 9 hijackable DLLs:

  CLASS          DLL                            SOURCE   STEALTH  DETAILS
  -----          ---                            ------   -------  -------
  [!] PHANTOM    sensapi.dll                    static   HIGH     Not in app dir [3 exports]
                 stealth: 3 exports (trivial proxy), direct import
  [!] PHANTOM    version.dll                    static   HIGH     Not in app dir [17 exports]
                 stealth: 17 exports, direct import
  [!] PHANTOM    dwmapi.dll                     static   MED      Not in app dir [101 exports]
                 stealth: 101 exports (complex proxy), direct import
  [!] PHANTOM    crypt32.dll                    static   LOW      Not in app dir [307 exports]
                 stealth: 307 exports (massive proxy), EDR-watched, direct import
  [!] PHANTOM    wininet.dll                    static   LOW      Not in app dir [327 exports]
                 stealth: 327 exports (massive proxy), EDR-watched, direct import
```

## How It Works

1. Parse static imports and delay-load imports from the PE header
2. Optionally launch the target under the Debug API to capture runtime `LoadLibrary` calls
3. For each DLL, walk the Windows DLL search order and check directory writability
4. Follow import chains recursively (BFS) to find transitive dependencies
5. Classify each DLL by hijack potential
6. With `--exports`, read the PE export table of each hijackable DLL

### Classifications

| Class | Meaning | Attack |
|-------|---------|--------|
| `MISSING` | Not found anywhere in search path | Drop your DLL in app directory |
| `PHANTOM` | Loaded from System32, but app dir is searched first | Plant proxy DLL in app dir |
| `SIDELOAD` | Already present in app directory | Replace with proxy DLL |
| `KNOWN_DLL` | Protected by KnownDLLs registry | Not hijackable |
| `SAFE` | API set or other non-exploitable | -- |

Automatically filtered: KnownDLLs (from registry), loader-critical DLLs (ntdll, kernelbase, etc.), API sets (api-ms-win-*, ext-ms-win-*).

## Usage

```
omnispex.exe [target.exe] [options]
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
| `--exports` | Show exports of hijackable DLLs (for proxy DLL generation) |
| `--timeout <secs>` | Dynamic analysis timeout (default: 30) |
| `--args <str>` | Arguments to pass to target during dynamic analysis |
| `--json` | Output JSON instead of table |
| `--show-all` | Include non-hijackable DLLs in output |
| `-v, --verbose` | Show search order, chain walk progress, per-module details |

### Examples

Local check with export enumeration:
```
omnispex.exe C:\Temp\npp\notepad++.exe --local --exports
```

Full analysis with dynamic tracing:
```
omnispex.exe C:\Temp\npp\notepad++.exe --timeout 15
```

Deep import chain walk (5 levels):
```
omnispex.exe C:\Temp\npp\notepad++.exe --local --depth 5 -v
```

Batch scan an entire program directory:
```
omnispex.exe --scan-dir "C:\Program Files\SomeVendor" --local
```

JSON for scripting (exports included in output):
```
omnispex.exe C:\Temp\npp\notepad++.exe --local --exports --json
```

## Stealth Scoring

Each hijackable DLL gets a stealth grade (HIGH / MED / LOW) based on how practical and covert the hijack would be:

| Factor | Effect | Why |
|--------|--------|-----|
| Export count | Fewer = higher | Proxy DLL with 3 forwards is trivial; 300+ is fragile and slow to build |
| EDR-watched | Penalty | crypt32, wintrust, bcrypt, ncrypt, wininet, winhttp, urlmon, amsi, dbghelp, ws2_32, dnsapi are heavily hooked by EDR products |
| SxS-redirected | Heavy penalty | App manifest declares SxS assembly dependency that overrides DLL search order -- loader resolves from WinSxS, not app dir |
| Delay-load | Bonus | Loaded lazily -- less likely to crash the app if the proxy has issues |
| Chain depth | Direct > deep | Direct imports load reliably; depth-3+ chains are more fragile |
| Class | MISSING > PHANTOM | MISSING = no original to deal with; PHANTOM = need a working proxy |

Results are sorted by class first, then stealth within each class, so the best targets float to the top.

### SxS Manifest Detection

Windows Side-by-Side (SxS) assemblies can override the normal DLL search order. When an executable's embedded manifest declares a dependency on an SxS assembly (e.g. `Microsoft.Windows.Common-Controls` v6), the loader resolves those DLLs from `WinSxS` instead of the application directory -- making DLL hijacking impossible for those specific DLLs.

Omnispex parses the embedded manifest from each target executable and flags affected DLLs with `SxS-redirected`. Common redirections:

| SxS Assembly | Redirected DLLs |
|-------------|-----------------|
| `Microsoft.Windows.Common-Controls` | comctl32.dll, msimg32.dll |
| `Microsoft.Windows.GdiPlus` | gdiplus.dll |

DLLs flagged as SxS-redirected receive a heavy stealth penalty and a warning in the output. While they still appear in the findings (the import exists), attempting to hijack them will fail at runtime.

## PE Metadata

The report header shows metadata parsed from the target's PE headers:

- **Architecture** and subsystem (x64/x86, GUI/Console)
- **Authenticode signature** status and signer name (extracted from embedded PKCS#7 certificate)
- **Version info** from the PE resource section: CompanyName, FileDescription, FileVersion, ProductName, OriginalFilename

This tells you at a glance what you're targeting — who signed it, what version it is, and whether it's the original binary or a renamed copy. Useful for confirming you have the right target before building a proxy DLL.

Note: Windows system binaries (notepad.exe, msiexec.exe) are often catalog-signed rather than Authenticode-signed. These show `Signed: NO` because they don't have an embedded certificate — the signature lives in a separate .cat file. Version info still works for these.

## Export Enumeration

`--exports` reads the PE export table of each hijackable DLL and lists every exported function with its ordinal, name, and forwarding target (if any). This is what you need to build a proxy DLL -- the exports tell you exactly what functions to forward.

For each DLL the tool shows:
- Total export count, ordinal-only exports, and forwarded exports
- Every function: ordinal number, name (or "ordinal only"), and forward target

The export data is also included in `--json` output, making it easy to feed into proxy DLL generators or C2 builders that need the export list.

## Batch Scan

`--scan-dir` recursively finds all `.exe` files (up to 10 levels deep), runs static analysis on each, and outputs a ranked table:

```
  OMNISPEX - BATCH SCAN
  ---------------------

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
  pe_parser.rs      PE import/export/metadata parsing (signature, version info)
  debugger.rs       Dynamic analysis via CreateProcessW + DEBUG_PROCESS
  search_order.rs   DLL search order walk, writability checks, classification
  known_dlls.rs     KnownDLLs registry + loader-critical DLL filtering
  report.rs         Table, JSON, and batch output formatting
```
