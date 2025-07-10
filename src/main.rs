use std::{fs, path::Path};

use spt_patcher::patcher::patch;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bpf_path =
        Path::new("/home/yui/Repositories/rust/spt_patcher/assets/Assembly-CSharp.dll.bpf");

    let input_path =
        Path::new("/home/yui/Repositories/rust/spt_patcher/assets/Assembly-CSharp.dll");

    let output = patch(input_path, bpf_path)?;
    fs::copy(input_path, input_path.with_extension("dll.spt-bak"))
        .expect("Error cloning input file.");
    fs::write(input_path, output).expect("Error replacing input with patched file");
    println!("File patched succesfully");
    Ok(())
}
