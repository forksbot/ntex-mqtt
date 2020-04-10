use super::{
    codec::FixedHeader, error::ParseError, packet::property_type as pt, packet::*, proto::*,
    ByteStr, UserProperty,
};
use bytes::buf::ext::{BufExt, Take as BufTake};
use bytes::{buf::ext::Take, Buf, Bytes};
use bytestring::ByteString;
use std::convert::{TryFrom, TryInto};
use std::io::Cursor;
use std::num::{NonZeroU16, NonZeroU32};

pub(crate) trait ByteBuf: Buf {
    fn inner_mut(&mut self) -> &mut Bytes;
}

impl ByteBuf for Bytes {
    fn inner_mut(&mut self) -> &mut Bytes {
        self
    }
}

impl ByteBuf for Take<&mut Bytes> {
    fn inner_mut(&mut self) -> &mut Bytes {
        self.get_mut()
    }
}

pub(crate) trait Property {
    fn init() -> Self;
    fn read_value<B: ByteBuf>(&mut self, src: &mut B) -> Result<(), ParseError>;
}

impl<T: Parse> Property for Option<T> {
    fn init() -> Self {
        None
    }

    fn read_value<B: ByteBuf>(&mut self, src: &mut B) -> Result<(), ParseError> {
        ensure!(self.is_none(), ParseError::MalformedPacket); // property is set twice while not allowed
        *self = Some(T::parse(src)?);
        Ok(())
    }
}

impl<T: Parse> Property for Vec<T> {
    fn init() -> Self {
        Vec::new()
    }

    fn read_value<B: ByteBuf>(&mut self, src: &mut B) -> Result<(), ParseError> {
        self.push(T::parse(src)?);
        Ok(())
    }
}

pub(crate) trait Parse: Sized {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError>;
}

impl Parse for bool {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        ensure!(src.has_remaining(), ParseError::InvalidLength); // expected more data within the field
        let v = src.get_u8();
        ensure!(v <= 0x1, ParseError::MalformedPacket); // value is invalid
        Ok(v == 0x1)
    }
}

impl Parse for u16 {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        ensure!(src.remaining() >= 2, ParseError::InvalidLength);
        Ok(src.get_u16())
    }
}

impl Parse for u32 {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        ensure!(src.remaining() >= 4, ParseError::InvalidLength); // expected more data within the field
        let val = src.get_u32();
        Ok(val)
    }
}

impl Parse for NonZeroU32 {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        let val = NonZeroU32::new(u32::parse(src)?).ok_or(ParseError::MalformedPacket)?;
        Ok(val)
    }
}

impl Parse for NonZeroU16 {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        Ok(NonZeroU16::new(u16::parse(src)?).ok_or(ParseError::MalformedPacket)?)
    }
}

impl Parse for Bytes {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        let len = u16::parse(src)? as usize;
        ensure!(src.remaining() >= len, ParseError::InvalidLength);
        Ok(src.inner_mut().split_to(len))
    }
}

impl Parse for ByteStr {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        let bytes = Bytes::parse(src)?;
        Ok(ByteString::try_from(bytes)?)
    }
}

impl Parse for UserProperty {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        let key = ByteStr::parse(src)?;
        let val = ByteStr::parse(src)?;
        Ok((key, val))
    }
}

impl Parse for SubscriptionOptions {
    fn parse<B: ByteBuf>(src: &mut B) -> Result<Self, ParseError> {
        ensure!(src.has_remaining(), ParseError::InvalidLength);
        let val = src.get_u8();
        let qos = (val & 0b0000_0011).try_into()?;
        let retain_handling = ((val & 0b0011_0000) >> 4).try_into()?;
        Ok(SubscriptionOptions {
            qos,
            no_local: val & 0b0000_0100 != 0,
            retain_as_published: val & 0b0000_1000 != 0,
            retain_handling,
        })
    }
}

pub(crate) fn read_packet(mut src: Bytes, header: FixedHeader) -> Result<Packet, ParseError> {
    match header.first_byte {
        packet_type::PUBLISH_START..=packet_type::PUBLISH_END => Ok(Packet::Publish(
            Publish::parse(src, header.first_byte & 0b0000_1111)?,
        )),
        packet_type::PUBACK => Ok(Packet::PublishAck(PublishAck::parse(&mut src)?)),
        packet_type::PINGREQ => Ok(Packet::PingRequest),
        packet_type::PINGRESP => Ok(Packet::PingResponse),
        packet_type::SUBSCRIBE => Ok(Packet::Subscribe(Subscribe::parse(&mut src)?)),
        packet_type::SUBACK => Ok(Packet::SubscribeAck(SubscribeAck::parse(&mut src)?)),
        packet_type::UNSUBSCRIBE => Ok(Packet::Unsubscribe(Unsubscribe::parse(&mut src)?)),
        packet_type::UNSUBACK => Ok(Packet::UnsubscribeAck(UnsubscribeAck::parse(&mut src)?)),
        packet_type::CONNECT => Ok(Packet::Connect(Connect::parse(&mut src)?)),
        packet_type::CONNACK => Ok(Packet::ConnectAck(ConnectAck::parse(&mut src)?)),
        packet_type::DISCONNECT => decode_disconnect_packet(&mut src),
        packet_type::AUTH => decode_auth_packet(&mut src),
        packet_type::PUBREC => Ok(Packet::PublishReceived(PublishAck::parse(&mut src)?)),
        packet_type::PUBREL => Ok(Packet::PublishRelease(PublishAck2::parse(&mut src)?)),
        packet_type::PUBCOMP => Ok(Packet::PublishComplete(PublishAck2::parse(&mut src)?)),
        _ => Err(ParseError::UnsupportedPacketType),
    }
}

pub fn decode_variable_length(src: &[u8]) -> Result<Option<(u32, usize)>, ParseError> {
    let mut cur = Cursor::new(src);
    match decode_variable_length_cursor(&mut cur) {
        Ok(len) => Ok(Some((len, cur.position() as usize))),
        Err(ParseError::MalformedPacket) => Ok(None),
        Err(e) => Err(e),
    }
}

#[allow(clippy::cast_lossless)] // safe: allow cast through `as` because it is type-safe
pub fn decode_variable_length_cursor<B: Buf>(src: &mut B) -> Result<u32, ParseError> {
    let mut shift: u32 = 0;
    let mut len: u32 = 0;
    loop {
        ensure!(src.has_remaining(), ParseError::MalformedPacket);
        let val = src.get_u8();
        len += ((val & 0b0111_1111u8) as u32) << shift;
        if val & 0b1000_0000 == 0 {
            return Ok(len);
        } else {
            ensure!(shift < 21, ParseError::InvalidLength);
            shift += 7;
        }
    }
}

fn decode_disconnect_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    if src.has_remaining() {
        let reason_code = src.get_u8().try_into()?;

        let mut session_expiry_interval_secs = None;
        let mut server_reference = None;
        let mut reason_string = None;
        let mut user_properties = Vec::new();

        let prop_src = &mut take_properties(src)?;
        while prop_src.has_remaining() {
            match prop_src.get_u8() {
                pt::SESS_EXPIRY_INT => session_expiry_interval_secs.read_value(prop_src)?,
                pt::REASON_STRING => reason_string.read_value(prop_src)?,
                pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
                pt::SERVER_REF => server_reference.read_value(prop_src)?,
                _ => return Err(ParseError::MalformedPacket),
            }
        }
        ensure!(!src.has_remaining(), ParseError::InvalidLength);

        Ok(Packet::Disconnect(Disconnect {
            reason_code,
            session_expiry_interval_secs,
            server_reference,
            reason_string,
            user_properties,
        }))
    } else {
        Ok(Packet::Disconnect(Disconnect {
            reason_code: DisconnectReasonCode::NormalDisconnection,
            session_expiry_interval_secs: None,
            server_reference: None,
            reason_string: None,
            user_properties: Vec::new(),
        }))
    }
}

fn decode_auth_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    if src.has_remaining() {
        ensure!(src.remaining() > 1, ParseError::InvalidLength);
        let reason_code = src.get_u8().try_into()?;

        let mut auth_method = None;
        let mut auth_data = None;
        let mut reason_string = None;
        let mut user_properties = Vec::new();

        if reason_code != AuthReasonCode::Success || src.has_remaining() {
            let prop_src = &mut take_properties(src)?;
            while prop_src.has_remaining() {
                match prop_src.get_u8() {
                    pt::AUTH_METHOD => auth_method.read_value(prop_src)?,
                    pt::AUTH_DATA => auth_data.read_value(prop_src)?,
                    pt::REASON_STRING => reason_string.read_value(prop_src)?,
                    pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
                    _ => return Err(ParseError::MalformedPacket),
                }
            }
            ensure!(!src.has_remaining(), ParseError::InvalidLength);
        }

        Ok(Packet::Auth(Auth {
            reason_code,
            auth_method,
            auth_data,
            reason_string,
            user_properties,
        }))
    } else {
        Ok(Packet::Auth(Auth {
            reason_code: AuthReasonCode::Success,
            auth_method: None,
            auth_data: None,
            reason_string: None,
            user_properties: Vec::new(),
        }))
    }
}

pub(crate) fn take_properties(src: &mut Bytes) -> Result<BufTake<&mut Bytes>, ParseError> {
    let prop_len = decode_variable_length_cursor(src)?;
    ensure!(
        src.remaining() >= prop_len as usize,
        ParseError::InvalidLength
    );

    Ok(src.take(prop_len as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec5::UserProperties;
    use bytestring::ByteString;

    fn packet_id(v: u16) -> NonZeroU16 {
        NonZeroU16::new(v).unwrap()
    }

    fn assert_decode_packet<B: AsRef<[u8]>>(bytes: B, res: Packet) {
        let bytes = bytes.as_ref();
        let fixed = bytes[0];
        let (len, consumed) = decode_variable_length(&bytes[1..]).unwrap().unwrap();
        let hdr = FixedHeader {
            first_byte: fixed,
            remaining_length: (bytes.len() - consumed - 1) as u32,
        };
        let cur = Bytes::copy_from_slice(&bytes[consumed + 1..]);
        let mut tmp = bytes::BytesMut::with_capacity(4096);
        ntex_codec::Encoder::encode(
            &mut crate::codec5::codec::Codec::new(),
            res.clone(),
            &mut tmp,
        );
        println!("expected: {:X?}", tmp.as_ref());
        assert_eq!(read_packet(cur, hdr), Ok(res));
    }

    #[test]
    fn test_decode_variable_length() {
        fn assert_variable_length<B: AsRef<[u8]> + 'static>(bytes: B, res: (u32, usize)) {
            assert_eq!(decode_variable_length(bytes.as_ref()), Ok(Some(res)));
        }

        assert_variable_length(b"\x7f\x7f", (127, 1));

        assert_eq!(decode_variable_length(b"\xff\xff\xff"), Ok(None));

        assert_eq!(
            decode_variable_length(b"\xff\xff\xff\xff\xff\xff"),
            Err(ParseError::InvalidLength)
        );

        assert_variable_length(b"\x00", (0, 1));
        assert_variable_length(b"\x7f", (127, 1));
        assert_variable_length(b"\x80\x01", (128, 2));
        assert_variable_length(b"\xff\x7f", (16383, 2));
        assert_variable_length(b"\x80\x80\x01", (16384, 3));
        assert_variable_length(b"\xff\xff\x7f", (2_097_151, 3));
        assert_variable_length(b"\x80\x80\x80\x01", (2_097_152, 4));
        assert_variable_length(b"\xff\xff\xff\x7f", (268_435_455, 4));
    }

    #[test]
    fn test_decode_connect_packets() {
        assert_eq!(
            Connect::parse(&mut Bytes::from_static(
                b"\x00\x04MQTT\x05\xC0\x00\x3C\x00\x00\x0512345\x00\x04user\x00\x04pass"
            )),
            Ok(Connect {
                protocol: Protocol::MQTT(5),
                clean_start: false,
                keep_alive: 60,
                client_id: ByteString::from_static("12345"),
                last_will: None,
                username: Some(ByteString::from_static("user")),
                password: Some(Bytes::from_static(&b"pass"[..])),
                session_expiry_interval_secs: None,
                auth_method: None,
                auth_data: None,
                request_problem_info: None,
                request_response_info: None,
                receive_max: None,
                topic_alias_max: 0,
                user_properties: Vec::new(),
                max_packet_size: None,
            })
        );

        assert_eq!(
            Connect::parse(&mut Bytes::from_static(
                b"\x00\x04MQTT\x05\x14\x00\x3C\x00\x00\x0512345\x00\x00\x05topic\x00\x07message"
            )),
            Ok(Connect {
                protocol: Protocol::MQTT(5),
                clean_start: false,
                keep_alive: 60,
                client_id: ByteString::from_static("12345"),
                last_will: Some(LastWill {
                    qos: QoS::ExactlyOnce,
                    retain: false,
                    topic: ByteString::from_static("topic"),
                    message: Bytes::from_static(&b"message"[..]),
                    will_delay_interval_sec: None,
                    correlation_data: None,
                    message_expiry_interval: None,
                    content_type: None,
                    user_properties: Vec::new(),
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
                user_properties: Vec::new(),
                max_packet_size: None,
            })
        );

        assert_eq!(
            Connect::parse(&mut Bytes::from_static(b"\x00\x02MQ00000000000000000000")),
            Err(ParseError::InvalidProtocol),
        );
        assert_eq!(
            Connect::parse(&mut Bytes::from_static(b"\x00\x04MQAA00000000000000000000")),
            Err(ParseError::InvalidProtocol),
        );
        assert_eq!(
            Connect::parse(&mut Bytes::from_static(
                b"\x00\x04MQTT\x0300000000000000000000"
            )),
            Err(ParseError::UnsupportedProtocolLevel),
        );
        assert_eq!(
            Connect::parse(&mut Bytes::from_static(
                b"\x00\x04MQTT\x05\xff00000000000000000000"
            )),
            Err(ParseError::ConnectReservedFlagSet)
        );

        assert_eq!(
            ConnectAck::parse(&mut Bytes::from_static(b"\x01\x04")),
            Ok(ConnectAck {
                session_present: true,
                reason_code: ConnectAckReasonCode::BadUserNameOrPassword,
                ..ConnectAck::default()
            })
        );

        assert_eq!(
            ConnectAck::parse(&mut Bytes::from_static(b"\x03\x04")),
            Err(ParseError::ConnAckReservedFlagSet)
        );

        assert_decode_packet(
            b"\x20\x02\x01\x04",
            Packet::ConnectAck(ConnectAck {
                session_present: true,
                reason_code: ConnectAckReasonCode::BadUserNameOrPassword,
                ..ConnectAck::default()
            }),
        );

        assert_decode_packet([0b1110_0000, 0], Packet::Disconnect(Disconnect::default()));
    }

    fn default_test_publish() -> Publish {
        Publish {
            dup: false,
            retain: false,
            qos: QoS::AtMostOnce,
            topic: ByteString::default(),
            packet_id: Some(packet_id(1)),
            payload: Bytes::new(),
            properties: PublishProperties::default(),
        }
    }

    #[test]
    fn test_decode_publish_packets() {
        //assert_eq!(
        //    decode_publish_packet(b"\x00\x05topic\x12\x34"),
        //    Done(&b""[..], ("topic".to_owned(), 0x1234))
        //);

        assert_decode_packet(
            b"\x3d\x0E\x00\x05topic\x43\x21\x00data",
            Packet::Publish(Publish {
                dup: true,
                retain: true,
                qos: QoS::ExactlyOnce,
                topic: ByteString::from_static("topic"),
                packet_id: Some(packet_id(0x4321)),
                payload: Bytes::from_static(b"data"),
                ..default_test_publish()
            }),
        );
        assert_decode_packet(
            b"\x30\x0C\x00\x05topic\x00data",
            Packet::Publish(Publish {
                dup: false,
                retain: false,
                qos: QoS::AtMostOnce,
                topic: ByteString::from_static("topic"),
                packet_id: None,
                payload: Bytes::from_static(b"data"),
                ..default_test_publish()
            }),
        );

        assert_decode_packet(
            b"\x40\x02\x43\x21",
            Packet::PublishAck(PublishAck {
                packet_id: packet_id(0x4321),
                reason_code: PublishAckReasonCode::Success,
                properties: AckProperties::default(),
            }),
        );
        assert_decode_packet(
            b"\x50\x02\x43\x21",
            Packet::PublishReceived(PublishAck {
                packet_id: packet_id(0x4321),
                reason_code: PublishAckReasonCode::Success,
                properties: AckProperties::default(),
            }),
        );
        assert_decode_packet(
            b"\x62\x02\x43\x21",
            Packet::PublishRelease(PublishAck2 {
                packet_id: packet_id(0x4321),
                reason_code: PublishAck2ReasonCode::Success,
                properties: AckProperties::default(),
            }),
        );
        assert_decode_packet(
            b"\x70\x02\x43\x21",
            Packet::PublishComplete(PublishAck2 {
                packet_id: packet_id(0x4321),
                reason_code: PublishAck2ReasonCode::Success,
                properties: AckProperties::default(),
            }),
        );
    }

    #[test]
    fn test_decode_subscribe_packets() {
        let p = Packet::Subscribe(Subscribe {
            packet_id: packet_id(0x1234),
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
            id: None,
            user_properties: Vec::new(),
        });

        assert_eq!(
            Packet::Subscribe(Subscribe::parse(&mut Bytes::from_static(
                b"\x12\x34\x00\x00\x04test\x01\x00\x06filter\x02"
            )).unwrap()),
            p.clone()
        );
        assert_decode_packet(b"\x82\x13\x12\x34\x00\x00\x04test\x01\x00\x06filter\x02", p);

        let p = Packet::SubscribeAck(SubscribeAck {
            packet_id: packet_id(0x1234),
            status: vec![
                SubscribeAckReasonCode::GrantedQos1,
                SubscribeAckReasonCode::UnspecifiedError,
                SubscribeAckReasonCode::GrantedQos2,
            ],
            properties: AckProperties::default(),
        });

        assert_eq!(
            Packet::Subscribe(Subscribe::parse(&mut Bytes::from_static(b"\x12\x34\x00\x01\x80\x02")).unwrap()),
            p.clone()
        );
        assert_decode_packet(b"\x90\x05\x12\x34\x00\x01\x80\x02", p);

        let p = Packet::Unsubscribe(Unsubscribe {
            packet_id: packet_id(0x1234),
            topic_filters: vec![
                ByteString::from_static("test"),
                ByteString::from_static("filter"),
            ],
            user_properties: UserProperties::default(),
        });

        assert_eq!(
            Packet::Unsubscribe(Unsubscribe::parse(&mut Bytes::from_static(
                b"\x12\x34\x00\x00\x04test\x00\x06filter"
            )).unwrap()),
            p.clone()
        );
        assert_decode_packet(b"\xa2\x11\x12\x34\x00\x00\x04test\x00\x06filter", p);

        assert_decode_packet(
            b"\xb0\x03\x43\x21\x00",
            Packet::UnsubscribeAck(UnsubscribeAck {
                packet_id: packet_id(0x4321),
                properties: AckProperties::default(),
                status: vec![],
            }),
        );
    }

    #[test]
    fn test_decode_ping_packets() {
        assert_decode_packet(b"\xc0\x00", Packet::PingRequest);
        assert_decode_packet(b"\xd0\x00", Packet::PingResponse);
    }
}
