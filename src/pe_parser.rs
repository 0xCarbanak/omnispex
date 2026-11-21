use std::collections::{HashMap, HashSet};

pub struct PeImports {
    pub imports: Vec<String>,
    pub delay_imports: Vec<String>,
}

pub struct PeExports {
    pub dll_name: String,
    pub functions: Vec<ExportEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportEntry {
    pub ordinal: u16,
    pub name: Option<String>,
    pub forward: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeInfo {
    pub arch: String,
    pub subsystem: String,
    pub timestamp: u32,
    pub is_signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
}

struct PeHeader {
    coff_offset: usize,
    optional_offset: usize,
    optional_magic: u16,
    num_dd: usize,
    dd_base: usize,
    sections: Vec<Section>,
}

fn parse_pe_header(data: &[u8]) -> Result<PeHeader, String> {
    if data.len() < 64 {
        return Err("file too small for PE".into());
    }
    if u16::from_le_bytes([data[0], data[1]]) != 0x5A4D {
        return Err("not a PE file (bad MZ magic)".into());
    }

    let pe_offset = read_u32(data, 60) as usize;
    if pe_offset + 4 > data.len() {
        return Err("bad PE offset".into());
    }
    if read_u32(data, pe_offset) != 0x00004550 {
        return Err("bad PE signature".into());
    }

    let coff_offset = pe_offset + 4;
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let optional_hdr_size = u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    let optional_offset = coff_offset + 20;
    if optional_offset + 2 > data.len() {
        return Err("optional header truncated".into());
    }
    let optional_magic = u16::from_le_bytes([data[optional_offset], data[optional_offset + 1]]);

    let (num_dd, dd_base) = match optional_magic {
        0x20B => {
            let ndd_off = optional_offset + 108;
            if ndd_off + 4 > data.len() {
                return Err("PE32+ header truncated".into());
            }
            (read_u32(data, ndd_off) as usize, optional_offset + 112)
        }
        0x10B => {
            let ndd_off = optional_offset + 92;
            if ndd_off + 4 > data.len() {
                return Err("PE32 header truncated".into());
            }
            (read_u32(data, ndd_off) as usize, optional_offset + 96)
        }
        _ => return Err(format!("unknown optional header magic: 0x{optional_magic:04X}")),
    };

    let sections_offset = optional_offset + optional_hdr_size;
    let sections = parse_sections(data, sections_offset, num_sections);

    Ok(PeHeader { coff_offset, optional_offset, optional_magic, num_dd, dd_base, sections })
}

pub fn parse_info(data: &[u8]) -> Result<PeInfo, String> {
    let hdr = parse_pe_header(data)?;

    let machine = u16::from_le_bytes([data[hdr.coff_offset], data[hdr.coff_offset + 1]]);
    let arch = match machine {
        0x8664 => "x64",
        0x014c => "x86",
        0xAA64 => "ARM64",
        _ => "unknown",
    }.to_string();

    let timestamp = read_u32(data, hdr.coff_offset + 4);

    let subsystem_off = if hdr.optional_magic == 0x20B {
        hdr.optional_offset + 68
    } else {
        hdr.optional_offset + 68
    };
    let subsystem = if subsystem_off + 2 <= data.len() {
        match u16::from_le_bytes([data[subsystem_off], data[subsystem_off + 1]]) {
            2 => "GUI",
            3 => "Console",
            1 => "Native",
            _ => "Other",
        }.to_string()
    } else {
        "Unknown".to_string()
    };

    // Certificate Table -- data directory index 4
    // NOTE: unlike other data dirs, this uses a FILE OFFSET not an RVA
    let is_signed = if hdr.num_dd > 4 {
        let cert_dd = hdr.dd_base + 4 * 8;
        if cert_dd + 8 <= data.len() {
            let cert_offset = read_u32(data, cert_dd) as usize;
            let cert_size = read_u32(data, cert_dd + 4) as usize;
            cert_offset != 0 && cert_size != 0
        } else {
            false
        }
    } else {
        false
    };

    let signer = if is_signed {
        let cert_dd = hdr.dd_base + 4 * 8;
        let cert_offset = read_u32(data, cert_dd) as usize;
        let cert_size = read_u32(data, cert_dd + 4) as usize;
        extract_signer_cn(data, cert_offset, cert_size)
    } else {
        None
    };

    // Version info from .rsrc section
    let vi = parse_version_info(data, &hdr);

    Ok(PeInfo {
        arch,
        subsystem,
        timestamp,
        is_signed,
        signer,
        company: vi.get("CompanyName").cloned(),
        description: vi.get("FileDescription").cloned(),
        file_version: vi.get("FileVersion").cloned(),
        product_name: vi.get("ProductName").cloned(),
        original_filename: vi.get("OriginalFilename").cloned(),
    })
}

fn extract_signer_cn(data: &[u8], cert_offset: usize, cert_size: usize) -> Option<String> {
    if cert_offset + cert_size > data.len() || cert_size < 8 {
        return None;
    }
    let cert_data = &data[cert_offset..cert_offset + cert_size];

    // WIN_CERTIFICATE: 4 bytes length, 2 bytes revision, 2 bytes type, then PKCS#7 data
    if cert_data.len() < 8 {
        return None;
    }
    let pkcs7 = &cert_data[8..];

    // Search for OID 2.5.4.3 (commonName) = 55 04 03
    // followed by a string type tag and length, then the CN string
    // Collect all unique CN values from the PKCS#7 certificates.
    // The signer's Subject CN is the one that isn't a CA — filter by keywords.
    let cn_oid: [u8; 3] = [0x55, 0x04, 0x03];
    let mut all_cns: Vec<String> = Vec::new();

    for i in 0..pkcs7.len().saturating_sub(5) {
        if pkcs7[i] != cn_oid[0] || pkcs7[i+1] != cn_oid[1] || pkcs7[i+2] != cn_oid[2] {
            continue;
        }
        let tag = pkcs7.get(i + 3).copied().unwrap_or(0);
        let cn = if tag == 0x0C || tag == 0x13 || tag == 0x16 {
            let len = pkcs7.get(i + 4).copied().unwrap_or(0) as usize;
            let start = i + 5;
            if start + len <= pkcs7.len() && len > 0 && len < 256 {
                Some(String::from_utf8_lossy(&pkcs7[start..start + len]).to_string())
            } else {
                None
            }
        } else if tag == 0x1E {
            let len = pkcs7.get(i + 4).copied().unwrap_or(0) as usize;
            let start = i + 5;
            if start + len <= pkcs7.len() && len > 1 && len < 512 && len % 2 == 0 {
                let chars: Vec<u16> = (0..len/2)
                    .map(|j| u16::from_be_bytes([pkcs7[start + j*2], pkcs7[start + j*2 + 1]]))
                    .collect();
                Some(String::from_utf16_lossy(&chars))
            } else {
                None
            }
        } else {
            None
        };

        if let Some(val) = cn {
            if !val.is_empty() && !all_cns.contains(&val) {
                all_cns.push(val);
            }
        }
    }

    // Leaf cert CN is typically shortest — CA certs include algo identifiers
    // (e.g. "SHA384 2021 CA1", "RSA2048-SHA256"). Filter obvious CAs first.
    let ca_markers = ["certificate authority", " ca1", " ca2", " ca3",
        "root ca", "signing ca", "code signing", "timestamping", " pca "];
    let mut candidates: Vec<String> = all_cns.into_iter().filter(|cn| {
        let l = cn.to_lowercase();
        !ca_markers.iter().any(|m| l.contains(m))
    }).collect();
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by_key(|c| c.len());
    Some(candidates.remove(0))
}

fn parse_version_info(data: &[u8], hdr: &PeHeader) -> HashMap<String, String> {
    let mut result = HashMap::new();

    // Resource directory -- data directory index 2
    if hdr.num_dd <= 2 {
        return result;
    }
    let rsrc_dd = hdr.dd_base + 2 * 8;
    if rsrc_dd + 8 > data.len() {
        return result;
    }
    let rsrc_rva = read_u32(data, rsrc_dd) as usize;
    if rsrc_rva == 0 {
        return result;
    }

    let Some(rsrc_offset) = rva_to_offset(rsrc_rva, &hdr.sections) else {
        return result;
    };

    // Find RT_VERSION (type 16) in root resource directory
    let Some(version_data) = find_resource(data, rsrc_offset, rsrc_rva, &hdr.sections, 16) else {
        return result;
    };

    // Parse VS_VERSIONINFO to find StringFileInfo strings
    extract_version_strings(version_data, &mut result);
    result
}

fn find_resource<'a>(data: &'a [u8], dir_offset: usize, rsrc_rva: usize, sections: &[Section], type_id: u16) -> Option<&'a [u8]> {
    // IMAGE_RESOURCE_DIRECTORY: 16 bytes header
    // then named entries, then ID entries
    if dir_offset + 16 > data.len() {
        return None;
    }
    let num_named = u16::from_le_bytes([data[dir_offset + 12], data[dir_offset + 13]]) as usize;
    let num_id = u16::from_le_bytes([data[dir_offset + 14], data[dir_offset + 15]]) as usize;

    let entries_start = dir_offset + 16;
    // Each entry is 8 bytes: ID/Name (4) + Offset (4)
    for i in num_named..(num_named + num_id) {
        let entry_off = entries_start + i * 8;
        if entry_off + 8 > data.len() {
            break;
        }
        let id = read_u32(data, entry_off);
        let offset_val = read_u32(data, entry_off + 4);

        if id as u16 == type_id {
            if offset_val & 0x80000000 != 0 {
                // Points to subdirectory
                let sub_off = (offset_val & 0x7FFFFFFF) as usize;
                let sub_dir = rsrc_rva_to_offset(sub_off, dir_offset, rsrc_rva, sections)?;
                return find_first_leaf(data, sub_dir, rsrc_rva, dir_offset, sections);
            } else {
                // Data entry
                let data_off = rsrc_rva_to_offset(offset_val as usize, dir_offset, rsrc_rva, sections)?;
                return read_resource_data(data, data_off, sections);
            }
        }
    }
    None
}

fn find_first_leaf<'a>(data: &'a [u8], dir_offset: usize, rsrc_rva: usize, rsrc_base: usize, sections: &[Section]) -> Option<&'a [u8]> {
    if dir_offset + 16 > data.len() {
        return None;
    }
    let num_named = u16::from_le_bytes([data[dir_offset + 12], data[dir_offset + 13]]) as usize;
    let num_id = u16::from_le_bytes([data[dir_offset + 14], data[dir_offset + 15]]) as usize;
    let total = num_named + num_id;
    if total == 0 {
        return None;
    }

    let entry_off = dir_offset + 16;
    if entry_off + 8 > data.len() {
        return None;
    }
    let offset_val = read_u32(data, entry_off + 4);

    if offset_val & 0x80000000 != 0 {
        let sub_off = (offset_val & 0x7FFFFFFF) as usize;
        let sub_dir = rsrc_rva_to_offset(sub_off, rsrc_base, rsrc_rva, sections)?;
        find_first_leaf(data, sub_dir, rsrc_rva, rsrc_base, sections)
    } else {
        let data_entry_off = rsrc_rva_to_offset(offset_val as usize, rsrc_base, rsrc_rva, sections)?;
        read_resource_data(data, data_entry_off, sections)
    }
}

fn rsrc_rva_to_offset(offset_from_rsrc: usize, rsrc_base_file: usize, _rsrc_rva: usize, _sections: &[Section]) -> Option<usize> {
    // Resource directory offsets are relative to the start of the resource section
    Some(rsrc_base_file + offset_from_rsrc)
}

fn read_resource_data<'a>(data: &'a [u8], data_entry_off: usize, sections: &[Section]) -> Option<&'a [u8]> {
    // IMAGE_RESOURCE_DATA_ENTRY: RVA (4), Size (4), CodePage (4), Reserved (4)
    if data_entry_off + 16 > data.len() {
        return None;
    }
    let data_rva = read_u32(data, data_entry_off) as usize;
    let data_size = read_u32(data, data_entry_off + 4) as usize;

    let file_offset = rva_to_offset(data_rva, sections)?;
    if file_offset + data_size > data.len() {
        return None;
    }
    Some(&data[file_offset..file_offset + data_size])
}

fn extract_version_strings(vi_data: &[u8], result: &mut HashMap<String, String>) {
    // VS_VERSIONINFO starts with wLength, wValueLength, wType, then "VS_VERSION_INFO\0" in UTF-16LE
    // We search for StringFileInfo and then individual String entries

    let keys = ["CompanyName", "FileDescription", "FileVersion", "ProductName",
                "ProductVersion", "OriginalFilename", "InternalName", "LegalCopyright"];

    for key in keys {
        if let Some(val) = find_version_string(vi_data, key) {
            if !val.is_empty() {
                result.insert(key.to_string(), val);
            }
        }
    }
}

fn find_version_string(data: &[u8], key: &str) -> Option<String> {
    // Encode key as UTF-16LE to search for it
    let key_utf16: Vec<u8> = key.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Search for the key in the version info data
    for i in 0..data.len().saturating_sub(key_utf16.len() + 4) {
        if data[i..].starts_with(&key_utf16) {
            // Check for null terminator after key
            let after_key = i + key_utf16.len();
            if after_key + 2 <= data.len() && data[after_key] == 0 && data[after_key + 1] == 0 {
                // Value follows after key null terminator, aligned to 4-byte boundary
                let value_start = align4(after_key + 2);
                if value_start + 2 <= data.len() {
                    return Some(read_utf16le_string(data, value_start));
                }
            }
        }
    }
    None
}

fn read_utf16le_string(data: &[u8], offset: usize) -> String {
    let mut chars = Vec::new();
    let mut i = offset;
    while i + 1 < data.len() {
        let c = u16::from_le_bytes([data[i], data[i + 1]]);
        if c == 0 {
            break;
        }
        chars.push(c);
        i += 2;
    }
    String::from_utf16_lossy(&chars)
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub fn parse_imports(data: &[u8]) -> Result<PeImports, String> {
    let hdr = parse_pe_header(data)?;

    let mut imports = Vec::new();
    let mut delay_imports = Vec::new();

    if hdr.num_dd > 1 {
        let import_dd = hdr.dd_base + 8;
        if import_dd + 8 <= data.len() {
            let import_rva = read_u32(data, import_dd) as usize;
            if import_rva != 0 {
                imports = parse_import_directory(data, import_rva, &hdr.sections);
            }
        }
    }

    if hdr.num_dd > 13 {
        let delay_dd = hdr.dd_base + 13 * 8;
        if delay_dd + 8 <= data.len() {
            let delay_rva = read_u32(data, delay_dd) as usize;
            if delay_rva != 0 {
                delay_imports = parse_delay_import_directory(data, delay_rva, &hdr.sections);
            }
        }
    }

    Ok(PeImports { imports, delay_imports })
}

pub fn parse_exports(data: &[u8]) -> Result<PeExports, String> {
    let hdr = parse_pe_header(data)?;

    if hdr.num_dd == 0 {
        return Err("no export directory".into());
    }

    let export_dd = hdr.dd_base;
    if export_dd + 8 > data.len() {
        return Err("export data directory truncated".into());
    }
    let export_rva = read_u32(data, export_dd) as usize;
    let export_size = read_u32(data, export_dd + 4) as usize;
    if export_rva == 0 {
        return Err("no exports".into());
    }

    let Some(export_offset) = rva_to_offset(export_rva, &hdr.sections) else {
        return Err("can't resolve export directory RVA".into());
    };

    if export_offset + 40 > data.len() {
        return Err("export directory truncated".into());
    }

    let name_rva = read_u32(data, export_offset + 12) as usize;
    let ordinal_base = read_u32(data, export_offset + 16) as u16;
    let num_functions = read_u32(data, export_offset + 20) as usize;
    let num_names = read_u32(data, export_offset + 24) as usize;
    let addr_table_rva = read_u32(data, export_offset + 28) as usize;
    let name_ptr_rva = read_u32(data, export_offset + 32) as usize;
    let ordinal_table_rva = read_u32(data, export_offset + 36) as usize;

    let dll_name = if name_rva != 0 {
        rva_to_offset(name_rva, &hdr.sections)
            .map(|off| read_cstring(data, off))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let mut ordinal_to_name: HashMap<u16, String> = HashMap::new();
    if let (Some(name_off), Some(ord_off)) = (
        rva_to_offset(name_ptr_rva, &hdr.sections),
        rva_to_offset(ordinal_table_rva, &hdr.sections),
    ) {
        for i in 0..num_names {
            let np = name_off + i * 4;
            let op = ord_off + i * 2;
            if np + 4 > data.len() || op + 2 > data.len() {
                break;
            }
            let fn_name_rva = read_u32(data, np) as usize;
            let ordinal_index = u16::from_le_bytes([data[op], data[op + 1]]);
            if let Some(fn_name_off) = rva_to_offset(fn_name_rva, &hdr.sections) {
                let name = read_cstring(data, fn_name_off);
                if !name.is_empty() {
                    ordinal_to_name.insert(ordinal_index, name);
                }
            }
        }
    }

    let mut functions = Vec::new();
    if let Some(addr_off) = rva_to_offset(addr_table_rva, &hdr.sections) {
        for i in 0..num_functions {
            let entry_off = addr_off + i * 4;
            if entry_off + 4 > data.len() {
                break;
            }
            let func_rva = read_u32(data, entry_off) as usize;
            if func_rva == 0 {
                continue;
            }

            let ordinal = ordinal_base.wrapping_add(i as u16);
            let name = ordinal_to_name.get(&(i as u16)).cloned();

            let forward = if func_rva >= export_rva && func_rva < export_rva + export_size {
                rva_to_offset(func_rva, &hdr.sections)
                    .map(|off| read_cstring(data, off))
            } else {
                None
            };

            functions.push(ExportEntry { ordinal, name, forward });
        }
    }

    functions.sort_by(|a, b| match (&a.name, &b.name) {
        (Some(an), Some(bn)) => an.cmp(bn),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.ordinal.cmp(&b.ordinal),
    });

    Ok(PeExports { dll_name, functions })
}

fn parse_import_directory(data: &[u8], rva: usize, sections: &[Section]) -> Vec<String> {
    let mut dlls = Vec::new();
    let mut seen = HashSet::new();
    let Some(offset) = rva_to_offset(rva, sections) else { return dlls };

    let mut pos = offset;
    loop {
        if pos + 20 > data.len() { break }
        let name_rva = read_u32(data, pos + 12) as usize;
        if name_rva == 0 { break }
        if let Some(name_off) = rva_to_offset(name_rva, sections) {
            let name = read_cstring(data, name_off).to_lowercase();
            if !name.is_empty() && seen.insert(name.clone()) {
                dlls.push(name);
            }
        }
        pos += 20;
    }
    dlls
}

fn parse_delay_import_directory(data: &[u8], rva: usize, sections: &[Section]) -> Vec<String> {
    let mut dlls = Vec::new();
    let mut seen = HashSet::new();
    let Some(offset) = rva_to_offset(rva, sections) else { return dlls };

    let mut pos = offset;
    loop {
        if pos + 32 > data.len() { break }
        let name_rva = read_u32(data, pos + 4) as usize;
        if name_rva == 0 { break }
        if let Some(name_off) = rva_to_offset(name_rva, sections) {
            let name = read_cstring(data, name_off).to_lowercase();
            if !name.is_empty() && seen.insert(name.clone()) {
                dlls.push(name);
            }
        }
        pos += 32;
    }
    dlls
}

struct Section {
    virtual_address: usize,
    virtual_size: usize,
    raw_offset: usize,
    raw_size: usize,
}

fn parse_sections(data: &[u8], offset: usize, count: usize) -> Vec<Section> {
    let mut sections = Vec::new();
    for i in 0..count {
        let s = offset + i * 40;
        if s + 40 > data.len() { break }
        sections.push(Section {
            virtual_address: read_u32(data, s + 12) as usize,
            virtual_size: read_u32(data, s + 8) as usize,
            raw_offset: read_u32(data, s + 20) as usize,
            raw_size: read_u32(data, s + 16) as usize,
        });
    }
    sections
}

fn rva_to_offset(rva: usize, sections: &[Section]) -> Option<usize> {
    for s in sections {
        if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
            let delta = rva - s.virtual_address;
            if delta < s.raw_size {
                return Some(s.raw_offset + delta);
            }
        }
    }
    None
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_cstring(data: &[u8], offset: usize) -> String {
    let mut s = String::new();
    let mut i = offset;
    while i < data.len() && data[i] != 0 {
        s.push(data[i] as char);
        i += 1;
    }
    s
}
