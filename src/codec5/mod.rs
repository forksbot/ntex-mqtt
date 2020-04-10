#![allow(clippy::type_complexity, clippy::new_ret_no_self)]
//! MQTT v5 Protocol codec

use bytestring::ByteString;

#[macro_use]
mod error;
#[macro_use]
mod proto;
mod codec;
mod packet;
mod parse;
mod encode;

pub use self::codec::Codec;
pub use self::error::ParseError;
pub use self::packet::*;
pub use self::proto::{Protocol, QoS};
pub use crate::topic::{Level, Topic, TopicError};

// http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
pub const TCP_PORT: u16 = 1883;
pub const SSL_PORT: u16 = 8883;

/// Max possible packet size
pub(crate) const MAX_PACKET_SIZE: u32 = 0xF_FF_FF_FF;

pub(crate) type ByteStr = ByteString;
pub(crate) type UserProperty = (ByteStr, ByteStr);
pub(crate) type UserProperties = Vec<UserProperty>;

