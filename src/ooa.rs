use std::io::{Read, Seek};

use byteorder::{ReadBytesExt, LE};

#[derive(Debug)]
pub struct Section {
    pub content_id: String,
    pub oep: usize,
    pub enc_blocks: Vec<EncBlock>,
    pub image_base: u64,
    pub size_of_image: u32,
    pub import_dir: DataDir,
    pub iat_dir: DataDir,
    pub reloc_dir: DataDir,
}

#[derive(Debug)]
pub struct Import {
    pub characteristics: u32,
    pub timedatestamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub fthunk: u32,
}

#[derive(Debug)]
pub struct Thunk {
    pub function: u32,
    pub data_addr: u32,
}

#[derive(Debug)]
pub struct DataDir {
    pub va: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct EncBlock {
    pub va: u32,
    pub raw_size: u32,
    pub virtual_size: u32,
    pub unk: u32,
    pub crc: u32,
    pub unk2: u32, // 0
    pub crc2: u32,
    pub pad: u32,         // 0
    pub file_offset: u32, // 0
    pub pad2: u64,        // 0
    pub pad3: u32,        // 0
}

pub fn read_import<T: Read + Seek + ReadBytesExt>(cursor: &mut T) -> Import {
    Import {
        characteristics: cursor.read_u32::<LE>().unwrap(),
        timedatestamp: cursor.read_u32::<LE>().unwrap(),
        forwarder_chain: cursor.read_u32::<LE>().unwrap(),
        name: cursor.read_u32::<LE>().unwrap(),
        fthunk: cursor.read_u32::<LE>().unwrap(),
    }
}

pub fn read_thunk<T: Read + Seek + ReadBytesExt>(cursor: &mut T) -> Thunk {
    Thunk {
        function: cursor.read_u32::<LE>().unwrap(),
        data_addr: cursor.read_u32::<LE>().unwrap(),
    }
}

pub fn read_data_dir<T: Read + Seek + ReadBytesExt>(cursor: &mut T) -> DataDir {
    DataDir {
        va: cursor.read_u32::<LE>().unwrap(),
        size: cursor.read_u32::<LE>().unwrap(),
    }
}

pub fn read_enc_block<T: Read + Seek + ReadBytesExt>(cursor: &mut T) -> EncBlock {
    EncBlock {
        va: cursor.read_u32::<LE>().unwrap(),
        raw_size: cursor.read_u32::<LE>().unwrap(),
        virtual_size: cursor.read_u32::<LE>().unwrap(),
        unk: cursor.read_u32::<LE>().unwrap(),
        crc: cursor.read_u32::<LE>().unwrap(),
        unk2: cursor.read_u32::<LE>().unwrap(), // 0
        crc2: cursor.read_u32::<LE>().unwrap(),
        pad: cursor.read_u32::<LE>().unwrap(),         // 0
        file_offset: cursor.read_u32::<LE>().unwrap(), // 0
        pad2: cursor.read_u64::<LE>().unwrap(),        // 0
        pad3: cursor.read_u32::<LE>().unwrap(),        // 0
    }
}
