use super::AckProperties;
use crate::codec5::{
    encode::{
        encode_opt_props, encoded_size_opt_props, var_int_len, var_int_len_from_size,
        write_variable_length, Encode, EncodeLtd,
    },
    parse::Parse,
    ParseError,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{convert::TryInto, num::NonZeroU16};

/// PUBACK/PUBREC message content
#[derive(Debug, PartialEq, Clone)]
pub struct PublishAck {
    /// Packet Identifier
    pub packet_id: NonZeroU16,
    pub reason_code: PublishAckReasonCode,
    pub properties: AckProperties,
}

/// PUBREL/PUBCOMP message content
#[derive(Debug, PartialEq, Clone)]
pub struct PublishAck2 {
    /// Packet Identifier
    pub packet_id: NonZeroU16,
    pub reason_code: PublishAck2ReasonCode,
    pub properties: AckProperties,
}

prim_enum! {
    /// PUBACK / PUBREC reason codes
    pub enum PublishAckReasonCode {
        Success = 0,
        NoMatchingSubscribers = 16,
        UnspecifiedError = 128,
        ImplementationSpecificError = 131,
        NotAuthorized = 135,
        TopicNameInvalid = 144,
        PacketIdentifierInUse = 145,
        ReceiveMaximumExceeded = 147,
        QuotaExceeded = 151,
        PayloadFormatInvalid = 153
    }
}

prim_enum! {
    /// PUBREL / PUBCOMP reason codes
    pub enum PublishAck2ReasonCode {
        Success = 0,
        PacketIdNotFound = 146
    }
}

impl PublishAck {
    pub(crate) fn parse(src: &mut Bytes) -> Result<Self, ParseError> {
        let packet_id = NonZeroU16::parse(src)?;
        let (reason_code, properties) = if src.has_remaining() {
            let reason_code = src.get_u8().try_into()?;
            let properties = AckProperties::parse(src)?;
            ensure!(!src.has_remaining(), ParseError::InvalidLength); // no bytes should be left
            (reason_code, properties)
        } else {
            (PublishAckReasonCode::Success, AckProperties::default())
        };

        Ok(Self {
            packet_id,
            reason_code,
            properties,
        })
    }
}

impl PublishAck2 {
    pub(crate) fn parse(src: &mut Bytes) -> Result<Self, ParseError> {
        let packet_id = NonZeroU16::parse(src)?;
        let (reason_code, properties) = if src.has_remaining() {
            let reason_code = src.get_u8().try_into()?;
            let properties = AckProperties::parse(src)?;
            ensure!(!src.has_remaining(), ParseError::InvalidLength); // no bytes should be left
            (reason_code, properties)
        } else {
            (PublishAck2ReasonCode::Success, AckProperties::default())
        };

        Ok(Self {
            packet_id,
            reason_code,
            properties,
        })
    }
}

impl EncodeLtd for PublishAck {
    fn encoded_size(&self, limit: u32) -> usize {
        const HEADER_LEN: u32 = 2 + 1; // packet id + reason code
        let prop_len = self.properties.encoded_size(limit - HEADER_LEN - 4); // limit - HEADER_LEN - len(packet_len.max())
        HEADER_LEN as usize + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        write_variable_length(size, buf);
        self.packet_id.get().encode(buf)?;
        buf.put_u8(self.reason_code.into());
        self.properties.encode(buf, size - 3)?;
        Ok(())
    }
}

impl EncodeLtd for PublishAck2 {
    fn encoded_size(&self, limit: u32) -> usize {
        const HEADER_LEN: u32 = 2 + 1; // fixed header + packet id + reason code
        let prop_len = self.properties.encoded_size(limit - HEADER_LEN - 4); // limit - HEADER_LEN - packet_len.max()
        HEADER_LEN as usize + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        write_variable_length(size, buf);
        self.packet_id.get().encode(buf)?;
        buf.put_u8(self.reason_code.into());
        self.properties.encode(buf, size - 3)?;
        Ok(())
    }
}
