use std::{
    fs::File,
    io::{self, Read},
};

#[derive(Debug)]
pub struct PatchItem {
    pub offset: i32,
    pub data: Vec<u8>,
}

impl PatchItem {
    pub fn from_file(file: &mut File) -> io::Result<Self> {
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
