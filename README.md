# DLL Hijack Hunter

Standalone Windows tool that discovers DLL search order hijacking opportunities for a target executable. Combines static PE analysis with dynamic runtime monitoring to find hijackable DLLs.

## How It Works

Two analysis modes, combined by default:

- **Static** — Parses PE import table and delay-load imports, checks each DLL against the Windows search order
- **Dynamic** — Launches the target under the Windows Debug API, captures every DLL load event, analyzes actual load paths

Each DLL is classified:

| Class | Meaning | Attack |
|-------|---------|--------|
| `MISSING` | DLL not found anywhere in search path | Drop your DLL in app directory |
| `PHANTOM` | Loaded from System32, but app dir is searched first and writable | Plant proxy DLL in app dir |
| `WRITABLE_PATH` | Loaded from a writable PATH directory | Replace DLL in that directory |
| `SIDELOAD` | Already in app dir, directory is writable | Replace with proxy DLL |
| `KNOWN_DLL` | Protected by KnownDLLs registry | Not hijackable |
| `SAFE` | Not exploitable (non-writable location, API set, etc.) | — |

Automatically filters out:
- KnownDLLs (read from `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
- Loader-critical DLLs (ntdll, kernelbase, ucrtbase, etc. — kernel-mapped, not hijackable)
- API sets (api-ms-win-*, ext-ms-win-*)

## Usage

```
dll-hijack-hunter.exe <target.exe> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `--static-only` | Only parse PE imports (no execution) |
| `--dynamic-only` | Only run debug session |
| `--timeout <secs>` | Dynamic analysis timeout (default: 30) |
| `--args <str>` | Arguments to pass to target during dynamic analysis |
| `--json` | Output JSON instead of table |
| `--show-all` | Show all DLLs including non-hijackable |
| `-v, --verbose` | Show DLL search order and per-module details |

### Examples

Basic scan (static + dynamic):
```
dll-hijack-hunter.exe C:\Program Files\SomeApp\app.exe
```

Static only (no execution, safe for unknown binaries):
```
dll-hijack-hunter.exe C:\Tools\app.exe --static-only
```

Dynamic with custom timeout and arguments:
```
dll-hijack-hunter.exe C:\Tools\app.exe --timeout 15 --args "--config test.cfg"
```

JSON output for scripting:
```
dll-hijack-hunter.exe C:\Tools\app.exe --json
```

Verbose with all DLLs:
```
dll-hijack-hunter.exe C:\Tools\app.exe -v --show-all
```

## Building

Cross-compile from Linux:
```bash
cargo build --release --target x86_64-pc-windows-gnu
```

Build on Windows:
```
cargo build --release
```

Output: `target/x86_64-pc-windows-gnu/release/dll-hijack-hunter.exe` (~500KB)

## Architecture

```
src/
  main.rs           CLI and orchestration
  pe_parser.rs      PE import table + delay-load parsing
  debugger.rs       Dynamic analysis via CreateProcessW + DEBUG_PROCESS
  search_order.rs   DLL search order walk + writability checks + classification
  known_dlls.rs     KnownDLLs registry + loader-critical DLL filtering
  report.rs         Table and JSON output
```

### DLL Search Order (SafeDllSearchMode)

The tool walks the standard Windows DLL search order:

1. Application directory
2. System directory (System32)
3. Windows directory
4. Current working directory
5. PATH directories

For each DLL found in the PE imports or observed at runtime, it checks where the DLL exists in this order and whether those directories are writable.

### Static vs Dynamic

**Static analysis** reads the PE import table and delay-load directory directly from the binary. This finds all DLLs declared as dependencies without executing the target. Good for unknown or potentially malicious binaries.

**Dynamic analysis** launches the target under `DEBUG_PROCESS` and captures `LOAD_DLL_DEBUG_EVENT` messages. This catches DLLs loaded at runtime via `LoadLibrary` calls that aren't in the import table — plugins, COM objects, delay-loaded dependencies that actually get triggered, etc. The process is terminated after the timeout.

Combined mode runs both and merges results, tagging each finding with its source (`static`, `dynamic`, or `both`).
