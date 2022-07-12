use std::io::{Cursor, Seek, SeekFrom};

use byteorder::{ReadBytesExt, LE};

use crate::ooa::{read_data_dir, read_enc_block, read_import, read_thunk, Section};

/// Corresponds to `SHA1(b"5.02.15.92") ???`
pub const HASH: [u8; 20] = [
    214, 24, 5, 34, 117, 81, 199, 112, 69, 244, 93, 188, 146, 127, 63, 245, 249, 98, 11, 217,
];

pub fn parse(data: &[u8]) -> Section {
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
    loop {
        let tls_callback_va = cursor.read_u64::<LE>().unwrap();
        if tls_callback_va == 0 {
            break;
        }
    }

    // eprintln!("Offset: {:X} {:X}", cursor.position(), cursor.position() % 0x100);
    cursor
        .seek(SeekFrom::Current(
            (0x1ea - (cursor.position() as i64 % 0x100)) % 0x100,
        ))
        .unwrap();

    let oep = cursor.read_u32::<LE>().unwrap();
    let enc_blocks_count = cursor.read_u8().unwrap();
    let enc_blocks = (0..enc_blocks_count)
        .map(|_| read_enc_block(&mut cursor))
        .collect::<Vec<_>>();

    eprintln!("Offset: {:X}", cursor.position());

    cursor
        .seek(SeekFrom::Current(0x30 * (10 - enc_blocks_count as i64) + 8))
        .unwrap();
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
