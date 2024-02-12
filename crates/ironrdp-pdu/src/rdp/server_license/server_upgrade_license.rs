#[cfg(test)]
mod tests;

use std::io;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::{
    read_license_header, BlobHeader, BlobType, LicenseEncryptionData, LicenseHeader, PreambleType, ServerLicenseError,
    BLOB_LENGTH_SIZE, BLOB_TYPE_SIZE, MAC_SIZE, UTF16_NULL_TERMINATOR_SIZE, UTF8_NULL_TERMINATOR_SIZE,
};
use crate::crypto::rc4::Rc4;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::utils::CharacterSet;
use crate::{utils, PduDecode, PduEncode, PduParsing, PduResult};

const NEW_LICENSE_INFO_STATIC_FIELDS_SIZE: usize = 20;

/// [2.2.2.6] Server Upgrade License (SERVER_UPGRADE_LICENSE)
///
/// [2.2.2.6]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/e8339fbd-1fe3-42c2-a599-27c04407166d
#[derive(Debug, PartialEq, Eq)]
pub struct ServerUpgradeLicense {
    pub license_header: LicenseHeader,
    pub encrypted_license_info: Vec<u8>,
    pub mac_data: Vec<u8>,
}

impl ServerUpgradeLicense {
    pub fn verify_server_license(&self, encryption_data: &LicenseEncryptionData) -> Result<(), ServerLicenseError> {
        let mut rc4 = Rc4::new(encryption_data.license_key.as_slice());
        let decrypted_license_info = rc4.process(self.encrypted_license_info.as_slice());
        let mac_data =
            super::compute_mac_data(encryption_data.mac_salt_key.as_slice(), decrypted_license_info.as_ref());

        if mac_data != self.mac_data {
            return Err(ServerLicenseError::InvalidMacData);
        }

        Ok(())
    }
}

impl ServerUpgradeLicense {
    const NAME: &'static str = "ServerUpgradeLicense";
}

impl PduEncode for ServerUpgradeLicense {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> PduResult<()> {
        ensure_size!(in: dst, size: self.size());

        self.license_header.encode(dst)?;
        BlobHeader::new(BlobType::EncryptedData, self.encrypted_license_info.len()).encode(dst)?;
        dst.write_slice(&self.encrypted_license_info);
        dst.write_slice(&self.mac_data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        self.license_header.size() + BLOB_LENGTH_SIZE + BLOB_TYPE_SIZE + self.encrypted_license_info.len() + MAC_SIZE
    }
}

impl<'de> PduDecode<'de> for ServerUpgradeLicense {
    fn decode(src: &mut ReadCursor<'de>) -> PduResult<Self> {
        let license_header = read_license_header(PreambleType::NewLicense, src)?;

        if license_header.preamble_message_type != PreambleType::UpgradeLicense
            && license_header.preamble_message_type != PreambleType::NewLicense
        {
            return Err(invalid_message_err!(
                "preambleType",
                "got unexpected message preamble type"
            ));
        }

        let encrypted_license_info_blob = BlobHeader::decode(src)?;
        if encrypted_license_info_blob.blob_type != BlobType::EncryptedData {
            return Err(invalid_message_err!("blobType", "unexpected blob type"));
        }

        let encrypted_license_info = src.read_slice(encrypted_license_info_blob.length).into();
        let mac_data = src.read_slice(MAC_SIZE).into();

        Ok(Self {
            license_header,
            encrypted_license_info,
            mac_data,
        })
    }
}

impl_pdu_parsing_max!(ServerUpgradeLicense);

#[derive(Debug, PartialEq, Eq)]
pub struct NewLicenseInformation {
    pub version: u32,
    pub scope: String,
    pub company_name: String,
    pub product_id: String,
    pub license_info: Vec<u8>,
}

impl PduParsing for NewLicenseInformation {
    type Error = ServerLicenseError;

    fn from_buffer(mut stream: impl io::Read) -> Result<Self, Self::Error> {
        let version = stream.read_u32::<LittleEndian>()?;

        let scope_len = stream.read_u32::<LittleEndian>()?;
        let scope = utils::read_string_from_stream(
            &mut stream,
            scope_len as usize - UTF8_NULL_TERMINATOR_SIZE,
            CharacterSet::Ansi,
            true,
        )?;

        let company_name_len = stream.read_u32::<LittleEndian>()?;
        let company_name = utils::read_string_from_stream(
            &mut stream,
            company_name_len as usize - UTF16_NULL_TERMINATOR_SIZE,
            CharacterSet::Unicode,
            true,
        )?;

        let product_id_len = stream.read_u32::<LittleEndian>()?;
        let product_id = utils::read_string_from_stream(
            &mut stream,
            product_id_len as usize - UTF16_NULL_TERMINATOR_SIZE,
            CharacterSet::Unicode,
            true,
        )?;

        let license_info_len = stream.read_u32::<LittleEndian>()?;
        let mut license_info = vec![0u8; license_info_len as usize];
        stream.read_exact(&mut license_info)?;

        Ok(Self {
            version,
            scope,
            company_name,
            product_id,
            license_info,
        })
    }

    fn to_buffer(&self, mut stream: impl io::Write) -> Result<(), Self::Error> {
        stream.write_u32::<LittleEndian>(self.version)?;

        stream.write_u32::<LittleEndian>((self.scope.len() + UTF8_NULL_TERMINATOR_SIZE) as u32)?;
        utils::write_string_with_null_terminator(&mut stream, &self.scope, CharacterSet::Ansi)?;

        stream.write_u32::<LittleEndian>((self.company_name.len() * 2 + UTF16_NULL_TERMINATOR_SIZE) as u32)?;
        utils::write_string_with_null_terminator(&mut stream, &self.company_name, CharacterSet::Unicode)?;

        stream.write_u32::<LittleEndian>((self.product_id.len() * 2 + UTF16_NULL_TERMINATOR_SIZE) as u32)?;
        utils::write_string_with_null_terminator(&mut stream, &self.product_id, CharacterSet::Unicode)?;

        stream.write_u32::<LittleEndian>(self.license_info.len() as u32)?;
        stream.write_all(self.license_info.as_slice())?;

        Ok(())
    }

    fn buffer_length(&self) -> usize {
        NEW_LICENSE_INFO_STATIC_FIELDS_SIZE + self.scope.len() + UTF8_NULL_TERMINATOR_SIZE
        + self.company_name.len() * 2 // utf16
        + UTF16_NULL_TERMINATOR_SIZE
        + self.product_id.len() * 2 // utf16
        + UTF16_NULL_TERMINATOR_SIZE
        + self.license_info.len()
    }
}
