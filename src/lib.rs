use std::{error::Error, fs::read};

use refpack::{easy_decompress, format::*};

#[derive(Default, Clone, Copy)]
struct FileData {
    // Anything marked with [*] is used in both 7.1 and 7.0. Else, it's only in 7.1.
    itbtype: u32,   // 4 for full TGI, 5 or 6 for only GID and IID, and 7 for only IID.
    tid: u32,         // The Type ID of the file.
    gid: u32,         // The file's Group ID.
    iid: u64,         // [?] The file's Index ID.
    file_offset: u32, // The location of the file within the DBPF.
    fsz: u32,         // The size of the file in the DBPF, including compression.
    compressed: bool  // [*] Whether or not the file is compressed.
}

#[derive(Debug, Default)]
pub struct ReturnData {
    pub tid: u32,
    pub gid: u32,
    pub iid: u64,
    pub data: Vec<u8>,
}

#[derive(Default)]
struct DBPFHeader {
    major: u32,        // Major Version
    minor: u32,        // Minor Version
    index_count: u32,  // How many files are there?
    index_offset: u32, // Where is the index table?
    index_size: u32,   // How long is the index table?
}

pub fn decompress(fname: &str) -> Result<Vec<ReturnData>, Box<dyn Error>> {

    let data: Vec<u8> = read(fname)?;

    let mut hdr = DBPFHeader::default();
    
    parse_header(&mut hdr, &data)?;
    parse_index_table(&mut hdr, &data)
}

fn parse_header(hdr: &mut DBPFHeader, data: &[u8]) -> Result<(), Box<dyn Error>> {
    magic(data)?; // Check validity of file.

    hdr.major = u32::from_le_bytes(data[4..8].try_into()?);
    hdr.minor = u32::from_le_bytes(data[8..12].try_into()?);
    hdr.index_count = u32::from_le_bytes(data[36..40].try_into()?);
    if hdr.major == 1 {
        // As far as I've read, the pointer is here ONLY in versions 1 and 1.1.
        // It seems deprecated elsewhere.
        hdr.index_offset = u32::from_le_bytes(data[40..44].try_into()?);
    } else {
        // The normal location.
        hdr.index_offset = u32::from_le_bytes(data[64..68].try_into()?);
    }
    hdr.index_size = u32::from_le_bytes(data[44..48].try_into()?);
    // If something is deleted from the DBPF, it's a hole, however we can generally just ignore
    // them.

    Ok(())
}

fn parse_index_table(hdr: &mut DBPFHeader, data: &[u8]) -> Result<Vec<ReturnData>, Box<dyn Error>>  {
    let mut files: Vec<FileData> = Vec::with_capacity(hdr.index_count as usize);
    let mut freturn: Vec<ReturnData> = Vec::with_capacity(hdr.index_count as usize);

    let mut pointer = hdr.index_offset as usize;
    let mut itb = FileData::default();

    if hdr.major == 1 {
        for _ in 0..hdr.index_count {
            // DBPF 1.x uses Index 7.0...
            itb.tid = u32::from_le_bytes(data[pointer..pointer+4].try_into()?);
            itb.gid = u32::from_le_bytes(data[pointer+4..pointer+8].try_into()?);
            itb.iid = u32::from_le_bytes(data[pointer+8..pointer+12].try_into()?) as u64;
            itb.file_offset = u32::from_le_bytes(data[pointer+12..pointer+16].try_into()?);
            itb.fsz = u32::from_le_bytes(data[pointer+16..pointer+20].try_into()?);
            pointer += 20;

            files.push(itb);
        }
    } else {
        // And DBPF... Anything else doesn't! (i've only tested this with the spore galactic
        // adventures spec (3.0), so i can't verify this works in other games lol)
        itb.itbtype = u32::from_le_bytes(data[pointer..pointer+4].try_into()?);
        match &itb.itbtype {
            4 => {
                pointer += 8;
                for _ in 0..hdr.index_count {
                    itb.tid = u32::from_le_bytes(data[pointer..pointer+4].try_into()?);
                    itb.gid = u32::from_le_bytes(data[pointer+4..pointer+8].try_into()?);
                    itb.iid = u32::from_le_bytes(data[pointer+8..pointer+12].try_into()?) as u64;
                    itb.file_offset = u32::from_le_bytes(data[pointer+12..pointer+16].try_into()?);
                    itb.fsz = u32::from_le_bytes((data[pointer+16..pointer+20]).try_into()?) & !0x80000000;

                    itb.compressed = false;
                    if u16::from_le_bytes((data[pointer+24..pointer+26]).try_into()?) == 0xFFFF {
                        itb.compressed = true;
                    }

                    pointer += 28;

                    files.push(itb);
                }
            },
            5 | 6 => {
                itb.tid = u32::from_le_bytes(data[pointer+4..pointer+8].try_into()?);
                pointer += 12;
                for _ in 0..hdr.index_count {
                    itb.gid = u32::from_le_bytes(data[pointer+4..pointer+8].try_into()?);
                    itb.iid = u32::from_le_bytes(data[pointer+8..pointer+12].try_into()?) as u64;
                    itb.file_offset = u32::from_le_bytes(data[pointer+12..pointer+16].try_into()?);
                    itb.fsz = u32::from_le_bytes((data[pointer+16..pointer+20]).try_into()?) & !0x80000000;

                    itb.compressed = false;
                    if u16::from_le_bytes((data[pointer+24..pointer+26]).try_into()?) == 0xFFFF {
                        itb.compressed = true;
                    }


                    pointer += 24;

                    files.push(itb);
                }
            },
            7 => {
                itb.tid = u32::from_le_bytes(data[pointer+4..pointer+8].try_into()?);
                itb.gid = u32::from_le_bytes(data[pointer+8..pointer+12].try_into()?);
                pointer += 16;
                for _ in 0..hdr.index_count {
                    itb.gid = u32::from_le_bytes(data[pointer+4..pointer+8].try_into()?);
                    itb.iid = u32::from_le_bytes(data[pointer+8..pointer+12].try_into()?) as u64;
                    itb.file_offset = u32::from_le_bytes(data[pointer+12..pointer+16].try_into()?);
                    itb.fsz = u32::from_le_bytes((data[pointer+16..pointer+20]).try_into()?) & !0x80000000;

                    itb.compressed = false;
                    if u16::from_le_bytes((data[pointer+24..pointer+26]).try_into()?) == 0xFFFF {
                        itb.compressed = true;
                    }

                    pointer += 24;

                    files.push(itb);
                }
            },
            _ => {
                return Err("DeBPF: Error: File index type unrecognized!".into());
            },
        }
    }

    for file in files {
        let truedata = filer(data, &file, hdr)?;

        let frd = ReturnData {
            tid: file.tid,
            gid: file.gid,
            iid: file.iid,
            data: truedata
        };

        freturn.push(frd);
    }
    Ok(freturn)
}

fn filer(data: &[u8], file: &FileData, hdr: &mut DBPFHeader) -> Result<Vec<u8>, Box<dyn Error>> {
    let start = file.file_offset as usize;
    let end = start + file.fsz as usize;
    let chunk = &data[start..end];

    if file.compressed {
        let decompressed = if hdr.major == 1 {
            easy_decompress::<Maxis>(chunk)?
        } else {
            easy_decompress::<SimEA>(chunk)?
        };
        Ok(decompressed)
    } else {
        Ok(chunk.to_vec())
    }
}

fn magic(data: &[u8]) -> Result<(), Box<dyn Error>> {
    // Get the magic number. If this isn't DBPF, we quit with an error.
    if data[0..4] != [68,66,80,70] {
        return Err("DeBPF: Error: File is not DBPF!".into());
    }
    Ok(())
}
