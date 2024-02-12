#[cfg(test)]
mod test;

use std::io;
use std::io::Write;

use byteorder::{LittleEndian, ReadBytesExt as _, WriteBytesExt as _};
use md5::Digest;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive as _, ToPrimitive as _};

use super::{
    BasicSecurityHeader, BasicSecurityHeaderFlags, BlobHeader, BlobType, LicenseEncryptionData, LicenseHeader,
    PreambleFlags, PreambleType, PreambleVersion, ServerLicenseError, ServerPlatformChallenge, BLOB_LENGTH_SIZE,
    BLOB_TYPE_SIZE, MAC_SIZE, PLATFORM_ID, PREAMBLE_SIZE,
};
use crate::crypto::rc4::Rc4;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::{PduDecode, PduEncode, PduParsing, PduResult};

const RESPONSE_DATA_VERSION: u16 = 0x100;
const RESPONSE_DATA_STATIC_FIELDS_SIZE: usize = 8;

const CLIENT_HARDWARE_IDENTIFICATION_SIZE: usize = 20;

/// [2.2.2.5] Client Platform Challenge Response (CLIENT_PLATFORM_CHALLENGE_RESPONSE)
///
/// [2.2.2.5]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/f53ab87c-d07d-4bf9-a2ac-79542f7b456c
#[derive(Debug, PartialEq, Eq)]
pub struct ClientPlatformChallengeResponse {
    pub license_header: LicenseHeader,
    pub encrypted_challenge_response_data: Vec<u8>,
    pub encrypted_hwid: Vec<u8>,
    pub mac_data: Vec<u8>,
}

impl ClientPlatformChallengeResponse {
    const NAME: &'static str = "ClientPlatformChallengeResponse";

    pub fn from_server_platform_challenge(
        platform_challenge: &ServerPlatformChallenge,
        hostname: &str,
        encryption_data: &LicenseEncryptionData,
    ) -> Result<Self, ServerLicenseError> {
        let mut rc4 = Rc4::new(&encryption_data.license_key);
        let decrypted_challenge = rc4.process(platform_challenge.encrypted_platform_challenge.as_slice());

        let decrypted_challenge_mac =
            super::compute_mac_data(encryption_data.mac_salt_key.as_slice(), decrypted_challenge.as_slice());

        if decrypted_challenge_mac != platform_challenge.mac_data {
            return Err(ServerLicenseError::InvalidMacData);
        }

        let mut challenge_response_data = vec![0u8; RESPONSE_DATA_STATIC_FIELDS_SIZE];
        challenge_response_data.write_u16::<LittleEndian>(RESPONSE_DATA_VERSION)?;
        challenge_response_data.write_u16::<LittleEndian>(ClientType::Other.to_u16().unwrap())?;
        challenge_response_data.write_u16::<LittleEndian>(LicenseDetailLevel::Detail.to_u16().unwrap())?;
        challenge_response_data.write_u16::<LittleEndian>(decrypted_challenge.len() as u16)?;
        challenge_response_data.write_all(&decrypted_challenge)?;

        let mut hardware_id = Vec::with_capacity(CLIENT_HARDWARE_IDENTIFICATION_SIZE);
        let mut md5 = md5::Md5::new();
        md5.update(hostname.as_bytes());
        let hardware_data = &md5.finalize();

        hardware_id.write_u32::<LittleEndian>(PLATFORM_ID)?;
        hardware_id.write_all(hardware_data)?;

        let mut rc4 = Rc4::new(&encryption_data.license_key);
        let encrypted_hwid = rc4.process(&hardware_id);

        let mut rc4 = Rc4::new(&encryption_data.license_key);
        let encrypted_challenge_response_data = rc4.process(&challenge_response_data);

        challenge_response_data.extend(&hardware_id);
        let mac_data = super::compute_mac_data(
            encryption_data.mac_salt_key.as_slice(),
            challenge_response_data.as_slice(),
        );

        let license_header = LicenseHeader {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            preamble_message_type: PreambleType::PlatformChallengeResponse,
            preamble_flags: PreambleFlags::empty(),
            preamble_version: PreambleVersion::V3,
            preamble_message_size: (PREAMBLE_SIZE
                + (BLOB_TYPE_SIZE + BLOB_LENGTH_SIZE) * 2 // 2 blobs in this structure
                + MAC_SIZE + encrypted_challenge_response_data.len() + encrypted_hwid.len())
                as u16,
        };

        Ok(Self {
            license_header,
            encrypted_challenge_response_data,
            encrypted_hwid,
            mac_data,
        })
    }
}

impl PduEncode for ClientPlatformChallengeResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> PduResult<()> {
        ensure_size!(in: dst, size: self.size());

        self.license_header.encode(dst)?;

        BlobHeader::new(BlobType::EncryptedData, self.encrypted_challenge_response_data.len()).encode(dst)?;
        dst.write_slice(&self.encrypted_challenge_response_data);

        BlobHeader::new(BlobType::EncryptedData, self.encrypted_hwid.len()).encode(dst)?;
        dst.write_slice(&self.encrypted_hwid);

        dst.write_slice(&self.mac_data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        self.license_header.buffer_length()
        + (BLOB_TYPE_SIZE + BLOB_LENGTH_SIZE) * 2 // 2 blobs in this structure
        + MAC_SIZE + self.encrypted_challenge_response_data.len() + self.encrypted_hwid.len()
    }
}

impl<'de> PduDecode<'de> for ClientPlatformChallengeResponse {
    fn decode(src: &mut ReadCursor<'de>) -> PduResult<Self> {
        let license_header = LicenseHeader::decode(src)?;
        if license_header.preamble_message_type != PreambleType::PlatformChallengeResponse {
            return Err(invalid_message_err!(
                "preambleMessageType",
                "unexpected preamble message type"
            ));
        }

        let encrypted_challenge_blob = BlobHeader::decode(src)?;
        if encrypted_challenge_blob.blob_type != BlobType::EncryptedData {
            return Err(invalid_message_err!("blobType", "unexpected blob type"));
        }
        ensure_size!(in: src, size: encrypted_challenge_blob.length);
        let encrypted_challenge_response_data = src.read_slice(encrypted_challenge_blob.length).into();

        let encrypted_hwid_blob = BlobHeader::decode(src)?;
        if encrypted_hwid_blob.blob_type != BlobType::EncryptedData {
            return Err(invalid_message_err!("blobType", "unexpected blob type"));
        }
        ensure_size!(in: src, size: encrypted_hwid_blob.length);
        let encrypted_hwid = src.read_slice(encrypted_hwid_blob.length).into();

        let mac_data = src.read_slice(MAC_SIZE).into();

        Ok(Self {
            license_header,
            encrypted_challenge_response_data,
            encrypted_hwid,
            mac_data,
        })
    }
}

impl_pdu_parsing_max!(ClientPlatformChallengeResponse);

#[derive(Debug, PartialEq, FromPrimitive, ToPrimitive)]
enum ClientType {
    Win32 = 0x0100,
    Win16 = 0x0200,
    WinCe = 0x0300,
    Other = 0xff00,
}

#[derive(Debug, PartialEq, FromPrimitive, ToPrimitive)]
enum LicenseDetailLevel {
    Simple = 1,
    Moderate = 2,
    Detail = 3,
}

#[derive(Debug, PartialEq)]
pub(crate) struct PlatformChallengeResponseData {
    client_type: ClientType,
    license_detail_level: LicenseDetailLevel,
    challenge: Vec<u8>,
}

impl PduParsing for PlatformChallengeResponseData {
    type Error = ServerLicenseError;

    fn from_buffer(mut stream: impl io::Read) -> Result<Self, Self::Error> {
        let version = stream.read_u16::<LittleEndian>()?;
        if version != RESPONSE_DATA_VERSION {
            return Err(ServerLicenseError::InvalidChallengeResponseDataVersion);
        }

        let client_type = ClientType::from_u16(stream.read_u16::<LittleEndian>()?)
            .ok_or(ServerLicenseError::InvalidChallengeResponseDataClientType)?;

        let license_detail_level = LicenseDetailLevel::from_u16(stream.read_u16::<LittleEndian>()?)
            .ok_or(ServerLicenseError::InvalidChallengeResponseDataLicenseDetail)?;

        let challenge_len = stream.read_u16::<LittleEndian>()?;
        let mut challenge = vec![0u8; challenge_len as usize];
        stream.read_exact(&mut challenge)?;

        Ok(Self {
            client_type,
            license_detail_level,
            challenge,
        })
    }

    fn to_buffer(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u16::<LittleEndian>(RESPONSE_DATA_VERSION)?;
        stream.write_u16::<LittleEndian>(self.client_type.to_u16().unwrap())?;
        stream.write_u16::<LittleEndian>(self.license_detail_level.to_u16().unwrap())?;
        stream.write_u16::<LittleEndian>(self.challenge.len() as u16)?;
        stream.write_all(&self.challenge)?;

        Ok(())
    }

    fn buffer_length(&self) -> usize {
        RESPONSE_DATA_STATIC_FIELDS_SIZE + self.challenge.len()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientHardwareIdentification {
    pub(crate) platform_id: u32,
    pub(crate) data: Vec<u8>,
}

impl PduParsing for ClientHardwareIdentification {
    type Error = ServerLicenseError;

    fn from_buffer(mut stream: impl io::Read) -> Result<Self, Self::Error> {
        let platform_id = stream.read_u32::<LittleEndian>()?;

        let mut data = vec![0u8; MAC_SIZE];
        stream.read_exact(&mut data)?;

        Ok(Self { platform_id, data })
    }

    fn to_buffer(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u32::<LittleEndian>(self.platform_id)?;
        stream.write_all(&self.data)?;

        Ok(())
    }

    fn buffer_length(&self) -> usize {
        CLIENT_HARDWARE_IDENTIFICATION_SIZE
    }
}
