use std::collections::HashSet;

pub struct PeImports {
    pub imports: Vec<String>,
    pub delay_imports: Vec<String>,
}

pub fn parse_imports(data: &[u8]) -> Result<PeImports, String> {
    if data.len() < 64 {
        return Err("file too small for PE".into());
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return Err("not a PE file (bad MZ magic)".into());
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset + 4 > data.len() {
        return Err("bad PE offset".into());
    }

    let pe_sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);
    if pe_sig != 0x00004550 {
        return Err("bad PE signature".into());
    }

    let coff_offset = pe_offset + 4;
    let num_sections =
        u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let optional_hdr_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    let optional_offset = coff_offset + 20;
    if optional_offset + 2 > data.len() {
        return Err("optional header truncated".into());
    }
    let optional_magic =
        u16::from_le_bytes([data[optional_offset], data[optional_offset + 1]]);

    let (num_dd, dd_base) = match optional_magic {
        0x20B => {
            let ndd_off = optional_offset + 108;
            if ndd_off + 4 > data.len() {
                return Err("PE32+ header truncated".into());
            }
            let ndd = u32::from_le_bytes([
                data[ndd_off],
                data[ndd_off + 1],
                data[ndd_off + 2],
                data[ndd_off + 3],
            ]) as usize;
            (ndd, optional_offset + 112)
        }
        0x10B => {
            let ndd_off = optional_offset + 92;
            if ndd_off + 4 > data.len() {
                return Err("PE32 header truncated".into());
            }
            let ndd = u32::from_le_bytes([
                data[ndd_off],
                data[ndd_off + 1],
                data[ndd_off + 2],
                data[ndd_off + 3],
            ]) as usize;
            (ndd, optional_offset + 96)
        }
        _ => return Err(format!("unknown optional header magic: 0x{optional_magic:04X}")),
    };

    let sections_offset = optional_offset + optional_hdr_size;
    let sections = parse_sections(data, sections_offset, num_sections);

    let mut imports = Vec::new();
    let mut delay_imports = Vec::new();

    // Import Directory — data directory index 1
    if num_dd > 1 {
        let import_dd = dd_base + 1 * 8;
        if import_dd + 8 <= data.len() {
            let import_rva = read_u32(data, import_dd) as usize;
            if import_rva != 0 {
                imports = parse_import_directory(data, import_rva, &sections);
            }
        }
    }

    // Delay Import Directory — data directory index 13
    if num_dd > 13 {
        let delay_dd = dd_base + 13 * 8;
        if delay_dd + 8 <= data.len() {
            let delay_rva = read_u32(data, delay_dd) as usize;
            if delay_rva != 0 {
                delay_imports = parse_delay_import_directory(data, delay_rva, &sections);
            }
        }
    }

    Ok(PeImports {
        imports,
        delay_imports,
    })
}

fn parse_import_directory(
    data: &[u8],
    rva: usize,
    sections: &[Section],
) -> Vec<String> {
    let mut dlls = Vec::new();
    let mut seen = HashSet::new();

    let Some(offset) = rva_to_offset(rva, sections) else {
        return dlls;
    };

    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes
    // Name RVA is at offset 12 within the descriptor
    let mut pos = offset;
    loop {
        if pos + 20 > data.len() {
            break;
        }

        let name_rva = read_u32(data, pos + 12) as usize;
        if name_rva == 0 {
            break;
        }

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

fn parse_delay_import_directory(
    data: &[u8],
    rva: usize,
    sections: &[Section],
) -> Vec<String> {
    let mut dlls = Vec::new();
    let mut seen = HashSet::new();

    let Some(offset) = rva_to_offset(rva, sections) else {
        return dlls;
    };

    // Each IMAGE_DELAYLOAD_DESCRIPTOR is 32 bytes
    // DllNameRVA is at offset 4
    let mut pos = offset;
    loop {
        if pos + 32 > data.len() {
            break;
        }

        let name_rva = read_u32(data, pos + 4) as usize;
        if name_rva == 0 {
            break;
        }

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
        if s + 40 > data.len() {
            break;
        }
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
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
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
