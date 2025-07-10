use crate::patch::structs::PatchItem;
use std::fs::File;
use std::io::{self, Read};

#[derive(Debug)]
pub struct PatchInfo {
    pub original_checksum: [u8; 32],
    pub original_length: i32,
    pub patched_checksum: [u8; 32],
    pub patched_length: i32,
    pub items: Vec<PatchItem>,
}

impl PatchInfo {
    pub fn from_file(file: &mut File) -> io::Result<Self> {
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
        let item_count = i32::from_le_bytes(buf_patch_item_count);

        let mut items: Vec<PatchItem> = vec![];
        for _ in 0..item_count {
            match PatchItem::from_file(file) {
                Ok(pi) => items.push(pi),
                Err(e) => {
                    eprintln!("Failed to add item: {}", e);
                    continue;
                }
            }
        }

        Ok(Self {
            original_checksum: buf_original_checksum,
            patched_checksum: buf_patched_checksum,
            original_length,
            patched_length,
            items,
        })
    }
}
