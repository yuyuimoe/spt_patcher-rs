use core::fmt;
use std::{
    cmp,
    error::Error,
    fs::File,
    io::{self, Read},
    path::Path,
};

#[derive(Debug, PartialEq)]
enum PatcherError {
    InvalidChecksum,
    CouldNotReadFile,
}

impl fmt::Display for PatcherError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cause = match *self {
            PatcherError::InvalidChecksum => {
                "Input file checksum does not match expectation by the bpf"
            }
            PatcherError::CouldNotReadFile => "Unable to read file",
        };
        f.write_str(cause)
    }
}

impl Error for PatcherError {}

#[derive(Debug)]
struct PatchItem {
    offset: i32,
    data: Vec<u8>,
}

impl PatchItem {
    fn from_file(file: &mut File) -> io::Result<Self> {
        let mut offset_buf = [0u8; 4];
        file.read_exact(&mut offset_buf)?;
        let offset = i32::from_le_bytes(offset_buf);

        let mut data_length_buf = [0u8; 4];
        file.read_exact(&mut data_length_buf)?;
        let data_length = i32::from_le_bytes(data_length_buf);

        let mut data_buf = vec![0u8; data_length as usize];
        file.read_exact(&mut data_buf)?;

        Ok(Self {
            offset,
            data: data_buf,
        })
    }
}

#[derive(Debug)]
struct PatchInfo {
    original_checksum: [u8; 32],
    original_length: i32,
    patched_checksum: [u8; 32],
    patched_length: i32,
    items: Vec<PatchItem>,
}

fn bpf_validate(bpf: &mut File) -> io::Result<()> {
    let mut header = [0u8; 4];
    bpf.read_exact(&mut header)?;
    if header != *b"BYBA" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File is not a BPF file (Invalid Header)",
        ));
    }

    let mut major_ver = [0u8; 1];
    bpf.read_exact(&mut major_ver)?;
    if major_ver[0] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BPF has invalid major version",
        ));
    }

    let mut minor_ver = [0u8; 1];
    bpf.read_exact(&mut minor_ver)?;
    if minor_ver[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BPF as invalid minor version",
        ));
    }

    Ok(())
}

fn bpf_generate_info(file: &mut File) -> io::Result<PatchInfo> {
    let mut buf_original_checksum = [0u8; 32];
    let mut buf_original_length = [0u8; 4];

    file.read_exact(&mut buf_original_length)?;
    let original_length = i32::from_le_bytes(buf_original_length);
    file.read_exact(&mut buf_original_checksum)?;

    let mut buf_patched_checksum = [0u8; 32];
    let mut buf_patched_length = [0u8; 4];

    file.read_exact(&mut buf_patched_length)?;
    let patched_length = i32::from_le_bytes(buf_patched_length);
    file.read_exact(&mut buf_patched_checksum)?;

    let mut buf_patch_item_count = [0u8; 4];
    file.read_exact(&mut buf_patch_item_count)?;
    let patched_length = i32::from_le_bytes(buf_patch_item_count);

    let mut items: Vec<PatchItem> = vec![];
    for _ in 0..=patched_length {
        match PatchItem::from_file(file) {
            Ok(pi) => items.push(pi),
            Err(e) => {
                eprintln!("Failed to add item: {}", e);
                continue;
            }
        }
    }

    Ok(PatchInfo {
        original_checksum: buf_original_checksum,
        patched_checksum: buf_patched_checksum,
        original_length,
        patched_length,
        items,
    })
}

fn bpf_patch(input: &mut File, patch_info: PatchInfo) -> Result<bool, PatcherError> {
    let mut file_buffer: Vec<u8> = vec![];
    match input.read_to_end(&mut file_buffer) {
        Ok(_) => println!("Input file read succesfully"),
        Err(_) => return Err(PatcherError::CouldNotReadFile),
    };
    let input_hash = sha256::digest(file_buffer);
    // println!(
    //     "{:#?} / {:#?}",
    //     input_hash,
    //     String::from_utf8_lossy(&patch_info.original_checksum)
    // );
    // if patch_info.original_checksum != input_hash.as_bytes() {
    //     return Err(PatcherError::InvalidChecksum);
    // }
    //

    let patched_data = vec![0u8, patch_info.patched_length];
    let min_length = cmp::min(patch_info.original_length, patch_info.patched_length);
    // for item in patch_info.items {
    //     patched_data[item.offset..=item.data.len()].copy_from_slice(src);
    // }

    Ok(true)
}

fn main() {
    let file_path =
        Path::new("/home/yui/Repositories/rust/spt_patcher/assets/Assembly-CSharp.dll.bpf");

    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => panic!("Error opening file: {}", e),
    };

    match bpf_validate(&mut file) {
        Ok(()) => println!("BPF has been validated."),
        Err(e) => eprintln!("Error: {}", e),
    };

    let patch_info = match bpf_generate_info(&mut file) {
        Ok(f) => f,
        Err(e) => panic!("Error generating info: {}", e),
    };

    let file_to_be_patched =
        Path::new("/home/yui/Repositories/rust/spt_patcher/assets/Assembly-CSharp.dll");

    let mut assembly_csharp = match File::open(file_to_be_patched) {
        Ok(f) => f,
        Err(e) => panic!("Error opening file: {}", e),
    };

    match bpf_patch(&mut assembly_csharp, patch_info) {
        Ok(_) => println!("File patched in-memory succesfully"),
        Err(e) => eprintln!("Error patching file: {}", e),
    };
}
