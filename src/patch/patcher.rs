use std::{fs::File, path::Path};

use crate::{
    PatcherError,
    patch::{
        PatchInfo,
        bpf::{bpf_patch, bpf_validate_header},
    },
};

pub fn patch(input_path: &Path, bpf_path: &Path) -> Result<Vec<u8>, PatcherError> {
    let mut bpf_file = File::open(bpf_path).map_err(|_| PatcherError::CouldNotReadBpfFile)?;

    match bpf_validate_header(&mut bpf_file) {
        Ok(()) => println!("BPF file is valid"),
        Err(_) => return Err(PatcherError::InvalidBpfHeader),
    }

    let patch_info =
        PatchInfo::from_file(&mut bpf_file).map_err(|_| PatcherError::FailedToGenerateInfo)?;

    let mut input_file = File::open(input_path).map_err(|_| PatcherError::CouldNotReadInputFile)?;
    let patch = bpf_patch(&mut input_file, patch_info)?;
    Ok(patch)
}
