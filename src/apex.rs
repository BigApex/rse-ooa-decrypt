use std::io::{Cursor, Seek, SeekFrom};

use byteorder::{ReadBytesExt, LE};

use crate::ooa::{read_data_dir, read_enc_block, read_import, read_thunk, Section};

/// Corresponds to `SHA1(b"5.02.04.66")`
pub const HASH_S11_1: [u8; 20] = [250, 245, 169, 146, 9, 235, 14, 14, 206, 72, 175, 215, 8, 35, 218, 185, 77, 140, 48, 61];

pub fn parse_s11_1(data: &[u8]) -> Section {
    let content_id = {
        let (_, slice, _) = unsafe { (&data[0x42..0x241]).align_to::<u16>() };
        String::from_utf16_lossy(
            &slice[0..slice.iter().position(|&c| c == 0).unwrap_or(slice.len())],
        )
    };
    let mut cursor = Cursor::new(data);
    cursor.seek(SeekFrom::Start(0x242)).unwrap();
    loop {
        let import = read_import(&mut cursor);
        if import.characteristics == 0 {
            break;
        }
    }
    loop {
        let iat = read_thunk(&mut cursor);
        if iat.function == 0 {
            break;
        }
    }
    loop {
        let original = read_thunk(&mut cursor);
        if original.function == 0 {
            break;
        }
    }
    cursor.seek(SeekFrom::Current(72)).unwrap();
    let reloc_max_size = cursor.read_u32::<LE>().unwrap();
    let _reloc_new_size = cursor.read_u32::<LE>().unwrap();
    cursor
        .seek(SeekFrom::Current(reloc_max_size as i64))
        .unwrap();
    let _tls = cursor.read_u32::<LE>().unwrap();
    let _tls_callback = cursor.read_u32::<LE>().unwrap();
    let _tls_first_callback = cursor.read_u64::<LE>().unwrap();

    let oep = cursor.read_u32::<LE>().unwrap();
    let enc_blocks_count = cursor.read_u8().unwrap();
    let enc_blocks = (0..enc_blocks_count)
        .map(|_| read_enc_block(&mut cursor))
        .collect::<Vec<_>>();

    cursor.seek(SeekFrom::Current(392)).unwrap();
    let unk = cursor.read_u8().unwrap();
    debug_assert_eq!(unk, 1, "unk != 1");

    let image_base = cursor.read_u64::<LE>().unwrap();
    let size_of_image = cursor.read_u32::<LE>().unwrap();

    let import_dir = read_data_dir(&mut cursor);
    let reloc_dir = read_data_dir(&mut cursor);
    let iat_dir = read_data_dir(&mut cursor);

    Section {
        content_id,
        oep: oep as usize,
        enc_blocks,
        image_base,
        size_of_image,
        import_dir,
        reloc_dir,
        iat_dir,
    }
}