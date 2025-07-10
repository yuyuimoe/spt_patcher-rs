use crate::{
    PatcherError,
    patch::{structs::PatchInfo, validation::compare_sha256_bytes},
};
use std::{
    fs::File,
    io::{Error, ErrorKind, Read},
};

pub fn bpf_validate_header(bpf: &mut File) -> std::io::Result<()> {
    let mut header = [0u8; 4];
    bpf.read_exact(&mut header)?;
    if header != *b"BYBA" {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "File is not a BPF file (Invalid Header)",
        ));
    }

    let mut major_ver = [0u8; 1];
    bpf.read_exact(&mut major_ver)?;
    if major_ver[0] != 1 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "BPF has invalid major version",
        ));
    }

    let mut minor_ver = [0u8; 1];
    bpf.read_exact(&mut minor_ver)?;
    if minor_ver[0] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "BPF as invalid minor version",
        ));
    }

    Ok(())
}

pub fn bpf_patch(input: &mut File, patch_info: PatchInfo) -> Result<Vec<u8>, PatcherError> {
    let mut file_buffer: Vec<u8> = vec![];
    match input.read_to_end(&mut file_buffer) {
        Ok(_) => println!("Input file read succesfully"),
        Err(_) => return Err(PatcherError::CouldNotReadInputFile),
    };

    // Hash the input data.

    if compare_sha256_bytes(&file_buffer, patch_info.patched_checksum) {
        return Err(PatcherError::AlreadyPatched);
    }

    if !compare_sha256_bytes(&file_buffer, patch_info.original_checksum) {
        return Err(PatcherError::InvalidOriginalChecksum);
    }

    let mut patched_data = vec![0u8; patch_info.patched_length as usize];
    let min_length = std::cmp::min(patch_info.original_length, patch_info.patched_length);

    patched_data[..min_length as usize].copy_from_slice(&file_buffer[..min_length as usize]);
    for item in patch_info.items {
        let offset = item.offset as usize;
        patched_data[offset..offset + item.data.len()].copy_from_slice(&item.data);
    }

    //Check if patched data is valid before return
    if !compare_sha256_bytes(&patched_data, patch_info.patched_checksum) {
        return Err(PatcherError::InvalidPatchedChecksum);
    }

    Ok(patched_data)
}
