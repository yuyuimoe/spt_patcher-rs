use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

#[derive(Debug)]
struct PatchInfo {
    original_checksum: Vec<u8>,
    original_length: u32,
    patched_checksum: Vec<u8>,
    patched_length: u32,
}

fn bpf_validate<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let mut bpf = File::open(path)?;

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

fn main() {
    let file_path =
        Path::new("/home/yui/Repositories/rust/spt_patcher/assets/Assembly-CSharp.dll.bpf");
    match bpf_validate(file_path) {
        Ok(()) => println!("Validation works"),
        Err(e) => eprintln!("Error: {}", e),
    };
}
