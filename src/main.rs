use std::{fs::File, io::Read};

struct PatchInfo {
    original_checksum: Vec<u8>,
    original_length: u32,
    patched_checksum: Vec<u8>,
    patched_length: u32,
}

fn main() {
    let mut bpf_file_stream =
        File::open("/home/yui/Repositories/rust/spt_patcher/assets/Assembly-CSharp.dll.bpf")
            .expect("Something went wrong when trying to read the bpf file");

    let mut bpf_byba_buf: Vec<u8> = vec![0; 4];
    bpf_file_stream
        .read_exact(&mut bpf_byba_buf)
        .expect("Failed to read bpf magic.");

    if !String::from_utf8(bpf_byba_buf)
        .expect("Failed to convert the first 4 bytes into string")
        .eq(&String::from("BYBA"))
    {
        panic!("File is not a BPF (No BYBA signature)");
    }

    println!("Success");
}
