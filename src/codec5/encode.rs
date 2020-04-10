use crate::codec5::error::ParseError;
use crate::codec5::packet::property_type as pt;
use crate::codec5::packet::*;
use bytes::{BufMut, Bytes, BytesMut};
use std::num::{NonZeroU16, NonZeroU32};
use super::{UserProperties, ByteStr};

pub(crate) trait EncodeLtd {
    fn encoded_size(&self, limit: u32) -> usize;
    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError>;
}

pub(crate) trait Encode {
    fn encoded_size(&self) -> usize;

    #[must_use]
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError>;
}


impl EncodeLtd for Packet {
    fn encoded_size(&self, limit: u32) -> usize {
        // limit -= 5; // fixed header = 1, var_len(remaining.max_value()) = 4
        match self {
            Packet::Connect(connect) => connect.encoded_size(limit),
            Packet::Publish(publish) => publish.encoded_size(limit),
            Packet::ConnectAck(ack) => ack.encoded_size(limit),
            Packet::PublishAck(ack) | Packet::PublishReceived(ack) => ack.encoded_size(limit),
            Packet::PublishRelease(ack) | Packet::PublishComplete(ack) => {
                ack.encoded_size(limit)
            }
            Packet::Subscribe(sub) => sub.encoded_size(limit),
            Packet::SubscribeAck(ack) => ack.encoded_size(limit),
            Packet::Unsubscribe(unsub) => unsub.encoded_size(limit),
            Packet::UnsubscribeAck(ack) => ack.encoded_size(limit),
            Packet::PingRequest | Packet::PingResponse => 0,
            Packet::Disconnect(disconnect) => disconnect.encoded_size(limit),
            Packet::Auth(auth) => auth.encoded_size(limit),
        }
    }

    fn encode(&self, buf: &mut BytesMut, check_size: u32) -> Result<(), ParseError> {
        match self {
            Packet::Connect(connect) => {
                buf.put_u8(0b0001_0000);
                write_variable_length(check_size, buf);
                connect.encode(buf, check_size)
            }
            Packet::ConnectAck(ack) => {
                buf.put_u8(0b0010_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::Publish(publish) => {
                buf.put_u8(
                    0b0011_0000
                        | (u8::from(publish.qos) << 1)
                        | ((publish.dup as u8) << 3)
                        | (publish.retain as u8),
                );
                write_variable_length(check_size, buf);
                publish.encode(buf, check_size)
            }
            Packet::PublishAck(ack) => {
                buf.put_u8(0b0100_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::PublishReceived(ack) => {
                buf.put_u8(0b0101_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::PublishRelease(ack) => {
                buf.put_u8(0b0110_0010);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::PublishComplete(ack) => {
                buf.put_u8(0b0111_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::Subscribe(sub) => {
                buf.put_u8(0b1000_0010);
                write_variable_length(check_size, buf);
                sub.encode(buf, check_size)
            }
            Packet::SubscribeAck(ack) => {
                buf.put_u8(0b1001_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::Unsubscribe(unsub) => {
                buf.put_u8(0b1010_0010);
                write_variable_length(check_size, buf);
                unsub.encode(buf, check_size)
            }
            Packet::UnsubscribeAck(ack) => {
                buf.put_u8(0b1011_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::PingRequest => {
                buf.put_slice(&[0b1100_0000, 0]);
                Ok(())
            }
            Packet::PingResponse => {
                buf.put_slice(&[0b1101_0000, 0]);
                Ok(())
            }
            Packet::Disconnect(disconnect) => {
                buf.put_u8(0b1110_0000);
                write_variable_length(check_size, buf);
                disconnect.encode(buf, check_size)
            }
            Packet::Auth(auth) => {
                buf.put_u8(0b1111_0000);
                write_variable_length(check_size, buf);
                auth.encode(buf, check_size)
            }
        }
    }
}

impl EncodeLtd for Disconnect {
    fn encoded_size(&self, limit: u32) -> usize {
        const HEADER_LEN: usize = 1; // reason code

        let mut prop_len = encoded_property_size(&self.session_expiry_interval_secs)
            + encoded_property_size(&self.server_reference);
        let diag_len = encoded_size_opt_props(
            &self.user_properties,
            &self.reason_string,
            reduce_limit(limit, prop_len + HEADER_LEN + 4),
        ); // exclude other props and max of 4 bytes for property length value
        prop_len += diag_len;
        HEADER_LEN + var_int_len(prop_len) as usize + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        let start_len = buf.len();
        buf.put_u8(self.reason_code.into());

        let prop_len = var_int_len_from_size(size - 1);
        write_variable_length(prop_len, buf);
        encode_property(&self.session_expiry_interval_secs, pt::SESS_EXPIRY_INT, buf)?;
        encode_property(&self.server_reference, pt::SERVER_REF, buf)?;
        println!("size: {}, buf len: {}", size, buf.len());
        encode_opt_props(
            &self.user_properties,
            &self.reason_string,
            buf,
            size - (buf.len() - start_len) as u32,
        )
    }
}

impl EncodeLtd for Auth {
    fn encoded_size(&self, limit: u32) -> usize {
        const HEADER_LEN: usize = 1; // reason code

        let mut prop_len =
            encoded_property_size(&self.auth_method) + encoded_property_size(&self.auth_data);
        let diag_len = encoded_size_opt_props(
            &self.user_properties,
            &self.reason_string,
            reduce_limit(limit, prop_len + HEADER_LEN + 4),
        ); // exclude other props and max of 4 bytes for property length value
        prop_len += diag_len;
        HEADER_LEN + var_int_len(prop_len) as usize + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        let start_len = buf.len();
        buf.put_u8(self.reason_code.into());

        let prop_len = var_int_len_from_size(size - 1);
        write_variable_length(prop_len, buf);
        encode_property(&self.auth_method, pt::AUTH_METHOD, buf)?;
        encode_property(&self.auth_data, pt::AUTH_DATA, buf)?;
        encode_opt_props(
            &self.user_properties,
            &self.reason_string,
            buf,
            size - (buf.len() - start_len) as u32,
        )
    }
}

pub(crate) fn encoded_size_opt_props(
    user_props: &UserProperties,
    reason_str: &Option<ByteStr>,
    mut limit: u32,
) -> usize {
    let mut len = 0;
    for up in user_props.iter() {
        let prop_len = 1 + up.encoded_size(); // prop type byte + key.len() + val.len()
        if prop_len > limit as usize {
            return len;
        }
        limit -= prop_len as u32;
        len += prop_len;
    }

    if let Some(reason) = reason_str {
        let reason_len = reason.len() + 1; // safety: TODO: CHECK string length for being out of bounds (> u16::max_value())?
        if reason_len <= limit as usize {
            len += reason_len;
        }
    }

    len
}

pub(crate) fn encode_opt_props(
    user_props: &UserProperties,
    reason_str: &Option<ByteStr>,
    buf: &mut BytesMut,
    mut size: u32,
) -> Result<(), ParseError> {
    for up in user_props.iter() {
        let prop_len = 1 + up.0.encoded_size() + up.1.encoded_size(); // prop_type.len() + key.len() + val.len()
        if prop_len > size as usize {
            return Ok(());
        }
        buf.put_u8(pt::USER);
        up.encode(buf)?;
        size -= prop_len as u32; // safe: checked it's less already
    }

    if let Some(reason) = reason_str {
        if reason.len() < size as usize {
            buf.put_u8(pt::REASON_STRING);
            reason.encode(buf)?;
        }
    }

    // todo: debug_assert remaining is 0

    Ok(())
}

pub(crate) fn encoded_property_size<T: Encode>(v: &Option<T>) -> usize {
    v.as_ref().map_or(0, |v| 1 + v.encoded_size()) // 1 - property type byte
}

pub(crate) fn encode_property<T: Encode>(
    v: &Option<T>,
    prop_type: u8,
    buf: &mut BytesMut,
) -> Result<(), ParseError> {
    if let Some(v) = v {
        buf.put_u8(prop_type);
        v.encode(buf)
    } else {
        Ok(())
    }
}

/// Calculates length of variable length integer based on its value
pub(crate) fn var_int_len(val: usize) -> u32 {
    #[cfg(target_pointer_width = "16")]
    panic!("16-bit platforms are not supported");
    #[cfg(target_pointer_width = "32")]
    const MAP: [u32; 33] = [
        5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];
    #[cfg(target_pointer_width = "64")]
    const MAP: [u32; 65] = [
        10, 9, 9, 9, 9, 9, 9, 9, 8, 8, 8, 8, 8, 8, 8, 7, 7, 7, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6,
        5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1,
        1, 1, 1, 1, 1, 1, 1,
    ];
    let zeros = val.leading_zeros();
    unsafe { *MAP.get_unchecked(zeros as usize) } // safety: zeros will never be more than 65 by definition.
}

/// Calculates length of variable length integer based on its value
pub(crate) fn var_int_len_u32(val: u32) -> u32 {
    const MAP: [u32; 33] = [
        5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];
    let zeros = val.leading_zeros();
    unsafe { *MAP.get_unchecked(zeros as usize) } // safety: zeros will never be more than 32 by definition.
}

/// Calculates `len` from `var_int_len(len) + len` value
pub(crate) fn var_int_len_from_size(val: u32) -> u32 {
    let over_size = var_int_len_u32(val);
    let res = val - over_size + 1;
    val - var_int_len_u32(res)
}

pub(crate) fn write_variable_length(len: u32, dst: &mut BytesMut) {
    match len {
        0..=127 => dst.put_u8(len as u8),
        128..=16_383 => {
            dst.put_slice(&[((len & 0b0111_1111) | 0b1000_0000) as u8, (len >> 7) as u8])
        }
        16_384..=2_097_151 => {
            dst.put_slice(&[
                ((len & 0b0111_1111) | 0b1000_0000) as u8,
                (((len >> 7) & 0b0111_1111) | 0b1000_0000) as u8,
                (len >> 14) as u8,
            ]);
        }
        2_097_152..=268_435_455 => {
            dst.put_slice(&[
                ((len & 0b0111_1111) | 0b1000_0000) as u8,
                (((len >> 7) & 0b0111_1111) | 0b1000_0000) as u8,
                (((len >> 14) & 0b0111_1111) | 0b1000_0000) as u8,
                (len >> 21) as u8,
            ]);
        }
        _ => panic!("length is too big"), // todo: verify at higher level
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encoded_size(&self) -> usize {
        if let Some(v) = self {
            v.encoded_size()
        } else {
            0
        }
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        if let Some(v) = self {
            v.encode(buf)
        } else {
            Ok(())
        }
    }
}

impl Encode for bool {
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        if *self {
            buf.put_u8(0x1);
        } else {
            buf.put_u8(0x0);
        }
        Ok(())
    }
}

impl Encode for u16 {
    fn encoded_size(&self) -> usize {
        2
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        buf.put_u16(*self);
        Ok(())
    }
}

impl Encode for NonZeroU16 {
    fn encoded_size(&self) -> usize {
        2
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        self.get().encode(buf)
    }
}

impl Encode for u32 {
    fn encoded_size(&self) -> usize {
        4
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        buf.put_u32(*self);
        Ok(())
    }
}

impl Encode for NonZeroU32 {
    fn encoded_size(&self) -> usize {
        4
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        self.get().encode(buf)
    }
}

impl Encode for Bytes {
    fn encoded_size(&self) -> usize {
        2 + self.len()
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        buf.put_u16(self.len() as u16);
        buf.extend_from_slice(self.as_ref());
        Ok(())
    }
}

impl Encode for ByteStr {
    fn encoded_size(&self) -> usize {
        self.get_ref().encoded_size()
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        self.get_ref().encode(buf)
    }
}

impl Encode for (ByteStr, ByteStr) {
    fn encoded_size(&self) -> usize {
        self.0.encoded_size() + self.1.encoded_size()
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        self.0.encode(buf)?;
        self.1.encode(buf)
    }
}

impl Encode for UserProperties {
    fn encoded_size(&self) -> usize {
        let mut len = 0;
        for prop in self {
            len += 1 + prop.encoded_size();
        }
        len
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        for prop in self {
            buf.put_u8(pt::USER);
            prop.encode(buf)?;
        }
        Ok(())
    }
}

pub(crate) fn reduce_limit(limit: u32, reduction: usize) -> u32 {
    if reduction > limit as usize {
        return 0;
    }
    limit - (reduction as u32) // safe: by now we're sure `reduction` fits in u32
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use bytestring::ByteString;

    use super::*;
    use crate::codec5::MAX_PACKET_SIZE;
    use crate::codec5::proto::*;

    fn packet_id(v: u16) -> NonZeroU16 {
        NonZeroU16::new(v).unwrap()
    }

    #[test]
    fn test_encode_variable_length() {
        let mut v = BytesMut::new();

        write_variable_length(123, &mut v);
        assert_eq!(v, [123].as_ref());

        v.clear();

        write_variable_length(129, &mut v);
        assert_eq!(v, b"\x81\x01".as_ref());

        v.clear();

        write_variable_length(16_383, &mut v);
        assert_eq!(v, b"\xff\x7f".as_ref());

        v.clear();

        write_variable_length(2_097_151, &mut v);
        assert_eq!(v, b"\xff\xff\x7f".as_ref());

        v.clear();

        write_variable_length(268_435_455, &mut v);
        assert_eq!(v, b"\xff\xff\xff\x7f".as_ref());

        // assert!(v.write_variable_length(MAX_VARIABLE_LENGTH + 1).is_err())
    }

    #[test]
    fn test_encode_fixed_header() {
        let mut v = BytesMut::new();
        let p = Packet::PingRequest;

        assert_eq!(p.encoded_size(MAX_PACKET_SIZE), 0);
        p.encode(&mut v, 0).unwrap();
        assert_eq!(&v[..2], b"\xc0\x00".as_ref());

        v.clear();

        let p = Packet::Publish(Publish {
            dup: true,
            retain: true,
            qos: QoS::ExactlyOnce,
            topic: ByteString::from_static("topic"),
            packet_id: Some(packet_id(0x4321)),
            payload: (0..255).collect::<Vec<u8>>().into(),
            properties: PublishProperties::default(),
        });

        assert_eq!(p.encoded_size(MAX_PACKET_SIZE), 265);
        p.encode(&mut v, 265);
        assert_eq!(&v[..3], b"\x3d\x89\x02".as_ref());
    }

    fn assert_encode_packet(packet: &Packet, expected: &[u8]) {
        let mut v = BytesMut::with_capacity(1024);
        packet.encode(&mut v, packet.encoded_size(1024) as u32);
        assert_eq!(expected.len(), v.len());
        assert_eq!(&expected[..], &v[..]);
    }

    #[test]
    fn test_encode_connect_packets() {
        assert_encode_packet(
            &Packet::Connect(Connect {
                protocol: Protocol::MQTT(5),
                clean_start: false,
                keep_alive: 60,
                client_id: ByteString::from_static("12345"),
                last_will: None,
                username: Some(ByteString::from_static("user")),
                password: Some(Bytes::from_static(b"pass")),
                session_expiry_interval_secs: None,
                auth_method: None,
                auth_data: None,
                request_problem_info: None,
                request_response_info: None,
                receive_max: None,
                topic_alias_max: 0,
                user_properties: vec![],
                max_packet_size: None,
            }),
            &b"\x10\x1E\x00\x04MQTT\x05\xC0\x00\x3C\x00\x00\
\x0512345\x00\x04user\x00\x04pass"[..],
        );

        assert_encode_packet(
            &Packet::Connect(Connect {
                protocol: Protocol::MQTT(5),
                clean_start: false,
                keep_alive: 60,
                client_id: ByteString::from_static("12345"),
                last_will: Some(LastWill {
                    qos: QoS::ExactlyOnce,
                    retain: false,
                    topic: ByteString::from_static("topic"),
                    message: Bytes::from_static(b"message"),
                    will_delay_interval_sec: None,
                    correlation_data: None,
                    message_expiry_interval: None,
                    content_type: None,
                    user_properties: vec![],
                    is_utf8_payload: None,
                    response_topic: None,
                }),
                username: None,
                password: None,
                session_expiry_interval_secs: None,
                auth_method: None,
                auth_data: None,
                request_problem_info: None,
                request_response_info: None,
                receive_max: None,
                topic_alias_max: 0,
                user_properties: vec![],
                max_packet_size: None,
            }),
            &b"\x10\x23\x00\x04MQTT\x05\x14\x00\x3C\x00\x00\
\x0512345\x00\x00\x05topic\x00\x07message"[..],
        );

        assert_encode_packet(
            &Packet::Disconnect(Disconnect {
                reason_code: DisconnectReasonCode::NormalDisconnection,
                session_expiry_interval_secs: None,
                server_reference: None,
                reason_string: None,
                user_properties: vec![],
            }),
            b"\xe0\x02\x00\x00",
        );
    }

    #[test]
    fn test_encode_publish_packets() {
        assert_encode_packet(
            &Packet::Publish(Publish {
                dup: true,
                retain: true,
                qos: QoS::ExactlyOnce,
                topic: ByteString::from_static("topic"),
                packet_id: Some(packet_id(0x4321)),
                payload: Bytes::from_static(b"data"),
                properties: PublishProperties::default(),
            }),
            b"\x3d\x0E\x00\x05topic\x43\x21\x00data",
        );

        assert_encode_packet(
            &Packet::Publish(Publish {
                dup: false,
                retain: false,
                qos: QoS::AtMostOnce,
                topic: ByteString::from_static("topic"),
                packet_id: None,
                payload: Bytes::from_static(b"data"),
                properties: PublishProperties::default(),
            }),
            b"\x30\x0c\x00\x05topic\x00data",
        );
    }

    #[test]
    fn test_encode_subscribe_packets() {
        assert_encode_packet(
            &Packet::Subscribe(Subscribe {
                packet_id: packet_id(0x1234),
                id: None,
                user_properties: Vec::new(),
                topic_filters: vec![
                    (
                        ByteString::from_static("test"),
                        SubscriptionOptions {
                            qos: QoS::AtLeastOnce,
                            no_local: false,
                            retain_as_published: false,
                            retain_handling: RetainHandling::AtSubscribe,
                        },
                    ),
                    (
                        ByteString::from_static("filter"),
                        SubscriptionOptions {
                            qos: QoS::ExactlyOnce,
                            no_local: false,
                            retain_as_published: false,
                            retain_handling: RetainHandling::AtSubscribe,
                        },
                    ),
                ],
            }),
            b"\x82\x13\x12\x34\x00\x00\x04test\x01\x00\x06filter\x02",
        );

        assert_encode_packet(
            &Packet::SubscribeAck(SubscribeAck {
                packet_id: packet_id(0x1234),
                properties: AckProperties::default(),
                status: vec![
                    SubscribeAckReasonCode::GrantedQos1,
                    SubscribeAckReasonCode::UnspecifiedError,
                    SubscribeAckReasonCode::GrantedQos2,
                ],
            }),
            b"\x90\x06\x12\x34\x00\x01\x80\x02",
        );

        assert_encode_packet(
            &Packet::Unsubscribe(Unsubscribe {
                packet_id: packet_id(0x1234),
                topic_filters: vec![
                    ByteString::from_static("test"),
                    ByteString::from_static("filter"),
                ],
                user_properties: Vec::new(),
            }),
            b"\xa2\x11\x12\x34\x00\x00\x04test\x00\x06filter",
        );

        assert_encode_packet(
            &Packet::UnsubscribeAck(UnsubscribeAck {
                packet_id: packet_id(0x4321),
                properties: AckProperties::default(),
                status: vec![
                    UnsubscribeAckReasonCode::Success,
                    UnsubscribeAckReasonCode::NotAuthorized,
                ],
            }),
            b"\xb0\x05\x43\x21\x00\x00\x87",
        );
    }

    #[test]
    fn test_encode_ping_packets() {
        assert_encode_packet(&Packet::PingRequest, b"\xc0\x00");
        assert_encode_packet(&Packet::PingResponse, b"\xd0\x00");
    }
}
