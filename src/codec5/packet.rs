use crate::codec5::{
    encode::*, parse::*, property_type as pt, ByteStr, EncodeError, ParseError, UserProperties,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

mod auth;
mod connack;
mod connect;
mod disconnect;
mod pubacks;
mod publish;
mod subscribe;

pub use auth::*;
pub use connack::*;
pub use connect::*;
pub use disconnect::*;
pub use pubacks::*;
pub use publish::*;
pub use subscribe::*;

#[derive(Debug, PartialEq, Clone)]
/// MQTT Control Packets
pub enum Packet {
    /// Client request to connect to Server
    Connect(Connect),
    /// Connect acknowledgment
    ConnectAck(ConnectAck),
    /// Publish message
    Publish(Publish),
    /// Publish acknowledgment
    PublishAck(PublishAck),
    /// Publish received (assured delivery part 1)
    PublishReceived(PublishAck),
    /// Publish release (assured delivery part 2)
    PublishRelease(PublishAck2),
    /// Publish complete (assured delivery part 3)
    PublishComplete(PublishAck2),
    /// Client subscribe request
    Subscribe(Subscribe),
    /// Subscribe acknowledgment
    SubscribeAck(SubscribeAck),
    /// Unsubscribe request
    Unsubscribe(Unsubscribe),
    /// Unsubscribe acknowledgment
    UnsubscribeAck(UnsubscribeAck),
    /// PING request
    PingRequest,
    /// PING response
    PingResponse,
    /// Disconnection is advertised
    Disconnect(Disconnect),
    /// Auth exchange
    Auth(Auth),
}

pub(crate) mod packet_type {
    pub const CONNECT: u8 = 0b0001_0000;
    pub const CONNACK: u8 = 0b0010_0000;
    pub const PUBLISH_START: u8 = 0b0011_0000;
    pub const PUBLISH_END: u8 = 0b0011_1111;
    pub const PUBACK: u8 = 0b0100_0000;
    pub const PUBREC: u8 = 0b0101_0000;
    pub const PUBREL: u8 = 0b0110_0010;
    pub const PUBCOMP: u8 = 0b0111_0000;
    pub const SUBSCRIBE: u8 = 0b1000_0010;
    pub const SUBACK: u8 = 0b1001_0000;
    pub const UNSUBSCRIBE: u8 = 0b1010_0010;
    pub const UNSUBACK: u8 = 0b1011_0000;
    pub const PINGREQ: u8 = 0b1100_0000;
    pub const PINGRESP: u8 = 0b1101_0000;
    pub const DISCONNECT: u8 = 0b1110_0000;
    pub const AUTH: u8 = 0b1111_0000;
}

pub(crate) mod property_type {
    pub const UTF8_PAYLOAD: u8 = 0x01;
    pub const MSG_EXPIRY_INT: u8 = 0x02;
    pub const CONTENT_TYPE: u8 = 0x03;
    pub const RESP_TOPIC: u8 = 0x08;
    pub const CORR_DATA: u8 = 0x09;
    pub const SUB_ID: u8 = 0x0B;
    pub const SESS_EXPIRY_INT: u8 = 0x11;
    pub const ASSND_CLIENT_ID: u8 = 0x12;
    pub const SERVER_KA: u8 = 0x13;
    pub const AUTH_METHOD: u8 = 0x15;
    pub const AUTH_DATA: u8 = 0x16;
    pub const REQ_PROB_INFO: u8 = 0x17;
    pub const WILL_DELAY_INT: u8 = 0x18;
    pub const REQ_RESP_INFO: u8 = 0x19;
    pub const RESP_INFO: u8 = 0x1A;
    pub const SERVER_REF: u8 = 0x1C;
    pub const REASON_STRING: u8 = 0x1F;
    pub const RECEIVE_MAX: u8 = 0x21;
    pub const TOPIC_ALIAS_MAX: u8 = 0x22;
    pub const TOPIC_ALIAS: u8 = 0x23;
    pub const MAX_QOS: u8 = 0x24;
    pub const RETAIN_AVAIL: u8 = 0x25;
    pub const USER: u8 = 0x26;
    pub const MAX_PACKET_SIZE: u8 = 0x27;
    pub const WILDCARD_SUB_AVAIL: u8 = 0x28;
    pub const SUB_IDS_AVAIL: u8 = 0x29;
    pub const SHARED_SUB_AVAIL: u8 = 0x2A;
}

mod ack_props {
    use super::*;

    pub(crate) fn encoded_size(
        properties: &UserProperties,
        reason_string: &Option<ByteStr>,
        limit: u32,
    ) -> usize {
        if limit < 4 {
            // todo: not really needed in practice
            return 1; // 1 byte to encode property length = 0
        }

        let len = encoded_size_opt_props(properties, reason_string, limit - 4);
        var_int_len(len) as usize + len
    }

    pub(crate) fn encode(
        properties: &UserProperties,
        reason_string: &Option<ByteStr>,
        buf: &mut BytesMut,
        size: u32,
    ) -> Result<(), EncodeError> {
        debug_assert!(size > 0); // formalize in signature?

        if size == 1 {
            // empty properties
            buf.put_u8(0);
            return Ok(());
        }

        let size = var_int_len_from_size(size);
        write_variable_length(size, buf);
        encode_opt_props(properties, reason_string, buf, size)
    }

    /// Parses ACK properties (User and Reason String properties) from `src`
    pub(crate) fn parse(
        src: &mut Bytes,
    ) -> Result<(UserProperties, Option<ByteStr>), ParseError> {
        let prop_src = &mut take_properties(src)?;
        let mut reason_string = None;
        let mut user_props = Vec::new();
        while prop_src.has_remaining() {
            let prop_id = prop_src.get_u8();
            match prop_id {
                pt::REASON_STRING => reason_string.read_value(prop_src)?,
                pt::USER => user_props.push(<(ByteStr, ByteStr)>::parse(prop_src)?),
                _ => return Err(ParseError::MalformedPacket),
            }
        }

        Ok((user_props, reason_string))
    }
}
