use std::path::Path;

use pelite::pe64::{Pe, PeFile};
use pelite::FileMap;

use crate::util::{aes_decrypt_inplace, decrypt_dlf, dlf_get_cipher, get_dlf_auto};

mod apex;
mod ooa;
mod titanfall2;
mod util;

fn get_ooa_hash(data: &[u8]) -> Option<[u8; 20]> {
    if data.len() < 0x3E {
        None
    } else {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&data[0x2A..0x3E]);
        Some(hash)
    }
}

fn main() {
    let file = std::env::args().nth(1);
    // let key = std::env::args().nth(2);
    if let Some(path) = file {
        let file_map = FileMap::open(&path).expect("Error mapping PE file!");
        let file = PeFile::from_bytes(file_map.as_ref()).expect("Error parsing PE file!");
        // let optional_header = file.optional_header();
        let (sections_num, section_header) = {
            let section_header = file.section_headers().iter();
            (
                section_header.len(),
                section_header
                    .last()
                    .expect("Invalid PE File! Zero Sections"),
            )
        };
        debug_assert_eq!(section_header.name().unwrap(), ".ooa");
        let section = &(file_map.as_ref())[section_header.PointerToRawData as usize
            ..section_header.PointerToRawData as usize + section_header.SizeOfRawData as usize];
        let hash = get_ooa_hash(section).expect("Invalid .ooa section!");
        let section = match hash {
            titanfall2::HASH => titanfall2::parse(section),
            apex::HASH_S11_1 => apex::parse_s11_1(section),
            _ => {
                unreachable!("Unknown .ooa version hash!")
            }
        };
        debug_assert_eq!(file.optional_header().ImageBase, section.image_base);
        debug_assert_eq!(
            file.optional_header().SizeOfImage - 0x1000,
            section.size_of_image
        );
        println!("{:#X?}", section);

        let dlf = if let Some(dlf) = get_dlf_auto(&section.content_id) {
            Some(dlf)
        } else if let Some(path) = std::env::args().nth(2) {
            if let Ok(data) = std::fs::read(path) {
                Some(decrypt_dlf(&data))
            } else {
                None
            }
        } else {
            None
        }
        .expect("Can't find correct DLF file!");
        println!("DLF: {}", String::from_utf8_lossy(&dlf));
        let dlf_key = dlf_get_cipher(&dlf).expect("Failed to get CipherKey from DLF!");
        println!("Key: {:?}", &dlf_key);

        let mut new = (file_map.as_ref()[0..section_header.PointerToRawData as usize]).to_vec();
        let e_lfanew = file.dos_header().e_lfanew as usize;
        let file_header_size = 24usize;
        let optional_header_size = file.file_header().SizeOfOptionalHeader as usize;

        // Decrypt every section...
        for block in section.enc_blocks {
            let section = file
                .section_headers()
                .as_slice()
                .iter()
                .find(|s| s.VirtualAddress == block.va)
                .expect("Failed to find section for decryption!");
            let mut iv = [0u8; 16];
            iv[..].copy_from_slice(
                &new[section.PointerToRawData as usize - 0x10..section.PointerToRawData as usize],
            );
            aes_decrypt_inplace(
                &dlf_key,
                &iv,
                &mut new[section.PointerToRawData as usize
                    ..section.PointerToRawData as usize + section.SizeOfRawData as usize],
            );
            // fix padding of one block
            if new[section.PointerToRawData as usize + section.SizeOfRawData as usize - 0x10
                ..section.PointerToRawData as usize + section.SizeOfRawData as usize]
                == [0x10u8; 16]
            {
                new[section.PointerToRawData as usize + section.SizeOfRawData as usize - 0x10
                    ..section.PointerToRawData as usize + section.SizeOfRawData as usize]
                    .copy_from_slice(&[0u8; 16]);
            }
        }

        // decrement sections count
        let sections_num_off = e_lfanew + 6;
        new[sections_num_off..sections_num_off + 2]
            .copy_from_slice(&(sections_num as u16 - 1).to_le_bytes());

        // Zero section out
        let section_data_off =
            e_lfanew + file_header_size + optional_header_size + (sections_num as usize - 1) * 0x28;
        new[section_data_off..section_data_off + 0x28].fill(0);

        // fix size of image
        let size_of_image_off = e_lfanew + file_header_size + 56;
        new[size_of_image_off..size_of_image_off + 4]
            .copy_from_slice(&section.size_of_image.to_le_bytes());

        // fix OEP
        let oep_off = e_lfanew + file_header_size + 16;
        new[oep_off..oep_off + 4].copy_from_slice(&(section.oep as u32).to_le_bytes());

        // fix import directory
        let import_dir_off = e_lfanew + file_header_size + 120;
        new[import_dir_off..import_dir_off + 4]
            .copy_from_slice(&section.import_dir.va.to_le_bytes());
        new[import_dir_off + 4..import_dir_off + 8]
            .copy_from_slice(&section.import_dir.size.to_le_bytes());

        // fix reloc directory
        let reloc_dir_off = e_lfanew + file_header_size + 152;
        new[reloc_dir_off..reloc_dir_off + 4].copy_from_slice(&section.reloc_dir.va.to_le_bytes());
        new[reloc_dir_off + 4..reloc_dir_off + 8]
            .copy_from_slice(&section.reloc_dir.size.to_le_bytes());

        // fix iat directory
        let iat_off = e_lfanew + file_header_size + 208;
        new[iat_off..iat_off + 4].copy_from_slice(&section.iat_dir.va.to_le_bytes());
        new[iat_off + 4..iat_off + 8].copy_from_slice(&section.iat_dir.size.to_le_bytes());

        std::fs::write(
            if let Some(stem) = Path::new(&path).file_stem() {
                stem.to_str().unwrap_or("").to_owned() + "-unpacked.exe"
            } else {
                "unpacked.exe".to_owned()
            },
            &new,
        )
        .expect("Error writing file!");
    } else {
        eprint!("Invalid usage!");
    }
}
