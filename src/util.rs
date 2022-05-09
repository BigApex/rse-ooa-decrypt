use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

const DLF_KEY: [u8; 16] = [
    65, 50, 114, 45, 208, 130, 239, 176, 220, 100, 87, 197, 118, 104, 202, 9,
];
const IV: [u8; 16] = [0u8; 16];
const CIPHER_TAG: &str = "<CipherKey>";
const BASE64_16_LEN: usize = 24;

// Apex has weird behaviour when 0x1000-0x10 isn't full zeroes...
pub fn aes_decrypt(key: &[u8], iv: &[u8], enc: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(enc).unwrap()
}

pub fn aes_decrypt_inplace(key: &[u8], iv: &[u8], buf: &mut [u8]) {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt(buf).unwrap();
}

pub fn decrypt_dlf(data: &[u8]) -> Vec<u8> {
    aes_decrypt(&DLF_KEY, &IV, &data[0x41..])
}

// Good version is Windows only yeah...
// btw if anyone knows how to unretardaise this - lemme know plox
pub fn get_dlf_auto(content_id: &str) -> Option<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        let path = if let Ok(val) = std::env::var("ProgramData") {
            format!("{}\\Electronic Arts\\EA Services\\License\\", val)
        } else {
            "C:\\ProgramData\\Electronic Arts\\EA Services\\License\\".to_owned()
        };
        if let Ok(data) = std::fs::read(path.clone() + content_id + ".dlf") {
            Some(decrypt_dlf(&data))
        } else if let Ok(data) = std::fs::read(path + content_id + "_cached.dlf") {
            Some(decrypt_dlf(&data))
        } else if let Ok(data) = std::fs::read(content_id.to_owned() + ".dlf") {
            Some(decrypt_dlf(&data))
        } else if let Ok(data) = std::fs::read(content_id.to_owned() + "_cached.dlf") {
            Some(decrypt_dlf(&data))
        } else {
            None
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(data) = std::fs::read(content_id.to_owned() + ".dlf") {
            Some(decrypt_dlf(&data))
        } else if let Ok(data) = std::fs::read(content_id.to_owned() + "_cached.dlf") {
            Some(decrypt_dlf(&data))
        } else {
            None
        }
    }
}

pub fn dlf_get_cipher(dlf: &[u8]) -> Option<Vec<u8>> {
    let string = String::from_utf8_lossy(dlf);
    if let Some(pos) = string.find(CIPHER_TAG) {
        let pos = pos + CIPHER_TAG.len();
        // let string = &string[pos..pos + string[pos..].find('<').unwrap_or(string.len() - pos)];
        if let Ok(mut data) = base64::decode_config(
            &string[pos..pos + BASE64_16_LEN],
            base64::STANDARD.decode_allow_trailing_bits(true),
        ) {
            data.truncate(16);
            Some(data)
        } else {
            None
        }
    } else {
        None
    }
}
