use std::io;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::{BlobHeader, BlobType, ServerLicenseError, KEY_EXCHANGE_ALGORITHM_RSA};
use crate::{
    cursor::{ReadCursor, WriteCursor},
    PduDecode, PduEncode, PduParsing, PduResult,
};

pub const SIGNATURE_ALGORITHM_RSA: u32 = 1;
pub const PROP_CERT_NO_BLOBS_SIZE: usize = 8;
pub const PROP_CERT_BLOBS_HEADERS_SIZE: usize = 8;
pub const X509_CERT_LENGTH_FIELD_SIZE: usize = 4;
pub const X509_CERT_COUNT: usize = 4;
pub const RSA_KEY_PADDING_LENGTH: u32 = 8;
pub const RSA_SENTINEL: u32 = 0x3141_5352;
pub const RSA_KEY_SIZE_WITHOUT_MODULUS: usize = 20;

const MIN_CERTIFICATE_AMOUNT: usize = 2;
const MAX_CERTIFICATE_AMOUNT: usize = 200;
const MAX_CERTIFICATE_LEN: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum CertificateType {
    Proprietary(ProprietaryCertificate),
    X509(X509CertificateChain),
}

/// [2.2.1.4.2] X.509 Certificate Chain (X509 _CERTIFICATE_CHAIN)
///
/// [2.2.1.4.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/bf2cc9cc-2b01-442e-a288-6ddfa3b80d59
#[derive(Debug, PartialEq, Eq)]
pub struct X509CertificateChain {
    pub certificate_array: Vec<Vec<u8>>,
}

impl X509CertificateChain {
    const NAME: &'static str = "X509CertificateChain";
}

impl PduEncode for X509CertificateChain {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> PduResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u32(cast_length!("certArrayLen", self.certificate_array.len())?);

        for certificate in &self.certificate_array {
            dst.write_u32(cast_length!("certLen", certificate.len())?);
            dst.write_slice(certificate);
        }

        let padding_len = 8 + 4 * self.certificate_array.len(); // MSDN: A byte array of the length 8 + 4*NumCertBlobs
        write_padding!(dst, padding_len);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let certificates_length: usize = self
            .certificate_array
            .iter()
            .map(|certificate| certificate.len() + X509_CERT_LENGTH_FIELD_SIZE)
            .sum();
        let padding: usize = 8 + 4 * self.certificate_array.len();
        X509_CERT_COUNT + certificates_length + padding
    }
}

impl<'de> PduDecode<'de> for X509CertificateChain {
    fn decode(src: &mut ReadCursor<'de>) -> PduResult<Self> {
        let certificate_count = cast_length!("certCount", src.read_u32())?;
        if !(MIN_CERTIFICATE_AMOUNT..MAX_CERTIFICATE_AMOUNT).contains(&certificate_count) {
            return Err(invalid_message_err!("certCount", "invalid x509 certificate amount"));
        }

        let certificate_array: Vec<_> = (0..certificate_count)
            .map(|_| {
                let certificate_len = cast_length!("certLen", src.read_u32())?;
                if certificate_len > MAX_CERTIFICATE_LEN {
                    return Err(invalid_message_err!("certLen", "invalid x509 certificate length"));
                }

                let certificate = src.read_slice(certificate_len).into();

                Ok(certificate)
            })
            .collect::<Result<_, _>>()?;

        read_padding!(src, 8 + 4 * certificate_count); // MSDN: A byte array of the length 8 + 4*NumCertBlobs

        Ok(Self { certificate_array })
    }
}

impl_pdu_parsing_max!(X509CertificateChain);

/// [2.2.1.4.3.1.1] Server Proprietary Certificate (PROPRIETARYSERVERCERTIFICATE)
///
/// [2.2.1.4.3.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a37d449a-73ac-4f00-9b9d-56cefc954634
#[derive(Debug, PartialEq, Eq)]
pub struct ProprietaryCertificate {
    pub public_key: RsaPublicKey,
    pub signature: Vec<u8>,
}

impl PduParsing for ProprietaryCertificate {
    type Error = ServerLicenseError;

    fn from_buffer(mut stream: impl io::Read) -> Result<Self, Self::Error> {
        let signature_algorithm_id = stream.read_u32::<LittleEndian>()?;
        if signature_algorithm_id != SIGNATURE_ALGORITHM_RSA {
            return Err(ServerLicenseError::InvalidPropCertSignatureAlgorithmId);
        }

        let key_algorithm_id = stream.read_u32::<LittleEndian>()?;
        if key_algorithm_id != KEY_EXCHANGE_ALGORITHM_RSA {
            return Err(ServerLicenseError::InvalidPropCertKeyAlgorithmId);
        }

        let key_blob_header = BlobHeader::from_buffer(&mut stream)?;
        if key_blob_header.blob_type != BlobType::RsaKey {
            return Err(ServerLicenseError::InvalidBlobType);
        }
        let public_key = RsaPublicKey::from_buffer(&mut stream)?;

        let sig_blob_header = BlobHeader::from_buffer(&mut stream)?;
        if sig_blob_header.blob_type != BlobType::RsaSignature {
            return Err(ServerLicenseError::InvalidBlobType);
        }
        let mut signature = vec![0u8; sig_blob_header.length];
        stream.read_exact(&mut signature)?;

        Ok(Self { public_key, signature })
    }

    fn to_buffer(&self, mut stream: impl io::Write) -> Result<(), Self::Error> {
        stream.write_u32::<LittleEndian>(SIGNATURE_ALGORITHM_RSA)?;
        stream.write_u32::<LittleEndian>(KEY_EXCHANGE_ALGORITHM_RSA)?;

        BlobHeader::new(BlobType::RsaKey, self.public_key.buffer_length()).to_buffer(&mut stream)?;
        self.public_key.to_buffer(&mut stream)?;

        BlobHeader::new(BlobType::RsaSignature, self.signature.len()).to_buffer(&mut stream)?;
        stream.write_all(&self.signature)?;

        Ok(())
    }

    fn buffer_length(&self) -> usize {
        PROP_CERT_BLOBS_HEADERS_SIZE + PROP_CERT_NO_BLOBS_SIZE + self.public_key.buffer_length() + self.signature.len()
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct RsaPublicKey {
    pub public_exponent: u32,
    pub modulus: Vec<u8>,
}

impl PduParsing for RsaPublicKey {
    type Error = ServerLicenseError;

    fn from_buffer(mut stream: impl io::Read) -> Result<Self, Self::Error> {
        let magic = stream.read_u32::<LittleEndian>()?;
        if magic != RSA_SENTINEL {
            return Err(ServerLicenseError::InvalidRsaPublicKeyMagic);
        }

        let keylen = stream.read_u32::<LittleEndian>()?;

        let bitlen = stream.read_u32::<LittleEndian>()?;
        if keylen != (bitlen / 8) + 8 {
            return Err(ServerLicenseError::InvalidRsaPublicKeyLength);
        }

        let datalen = stream.read_u32::<LittleEndian>()?;
        if datalen != (bitlen / 8) - 1 {
            return Err(ServerLicenseError::InvalidRsaPublicKeyDataLength);
        }

        let public_exponent = stream.read_u32::<LittleEndian>()?;

        let mut modulus = vec![0u8; keylen as usize];
        stream.read_exact(&mut modulus)?;

        Ok(Self {
            public_exponent,
            modulus,
        })
    }

    fn to_buffer(&self, mut stream: impl io::Write) -> Result<(), Self::Error> {
        let keylen = self.modulus.len() as u32;
        let bitlen = (keylen - RSA_KEY_PADDING_LENGTH) * 8;
        let datalen = bitlen / 8 - 1;

        stream.write_u32::<LittleEndian>(RSA_SENTINEL)?; // magic
        stream.write_u32::<LittleEndian>(keylen)?;
        stream.write_u32::<LittleEndian>(bitlen)?;
        stream.write_u32::<LittleEndian>(datalen)?;
        stream.write_u32::<LittleEndian>(self.public_exponent)?;
        stream.write_all(&self.modulus)?;

        Ok(())
    }

    fn buffer_length(&self) -> usize {
        RSA_KEY_SIZE_WITHOUT_MODULUS + self.modulus.len()
    }
}
