#[cfg(test)]
mod tests;

use super::{FieldType, Header, PduType, HEADER_SIZE, PDU_WITH_DATA_MAX_SIZE, UNUSED_U8};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::{PduEncode, PduResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPdu {
    pub channel_id_type: FieldType,
    pub channel_id: u32,
    pub data_size: usize,
}

impl DataPdu {
    pub(crate) fn from_buffer(
        mut stream: impl std::io::Read,
        channel_id_type: FieldType,
        data_size: usize,
    ) -> Result<Self, crate::PduError> {
        let mut buf = [0; crate::legacy::MAX_PDU_SIZE];
        let len = match stream.read(&mut buf) {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(not_enough_bytes_err!(0, crate::legacy::MAX_PDU_SIZE));
            }
            Err(e) => return Err(custom_err!(e)),
        };
        let mut cur = ReadCursor::new(&buf[0..len]);
        Self::decode(&mut cur, channel_id_type, data_size)
    }

    pub(crate) fn to_buffer(&self, mut stream: impl std::io::Write) -> Result<(), crate::PduError> {
        to_buffer!(self, stream, size: self.size())
    }

    pub(crate) fn buffer_length(&self) -> usize {
        self.size()
    }
}

impl DataPdu {
    const NAME: &'static str = "DvcDataPdu";

    pub fn new(channel_id: u32, data_size: usize) -> Self {
        Self {
            channel_id_type: FieldType::U32,
            channel_id,
            data_size,
        }
    }

    pub(crate) fn decode(
        src: &mut ReadCursor<'_>,
        channel_id_type: FieldType,
        mut data_size: usize,
    ) -> PduResult<Self> {
        let channel_id = channel_id_type.read_according_to_type(src)?;
        data_size -= channel_id_type.size();

        let expected_max_data_size = PDU_WITH_DATA_MAX_SIZE - (HEADER_SIZE + channel_id_type.size());

        if data_size > expected_max_data_size {
            Err(invalid_message_err!("DvcDataPdu", "invalid message size"))
        } else {
            Ok(Self {
                channel_id_type,
                channel_id,
                data_size,
            })
        }
    }
}

impl PduEncode for DataPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> PduResult<()> {
        let dvc_header = Header {
            channel_id_type: self.channel_id_type as u8,
            pdu_dependent: UNUSED_U8,
            pdu_type: PduType::Data,
        };
        dvc_header.encode(dst)?;
        self.channel_id_type.write_according_to_type(dst, self.channel_id)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        HEADER_SIZE + self.channel_id_type.size()
    }
}
