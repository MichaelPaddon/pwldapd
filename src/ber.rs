/// Minimal BER encoder/decoder for the subset of ASN.1 used by LDAP.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BerError {
    #[error("Unexpected end of input")]
    UnexpectedEof,
    #[error("Long-form tag not supported")]
    LongFormTag,
    #[error("Unexpected tag: expected {expected:#04x}, got {got:#04x}")]
    UnexpectedTag { expected: u8, got: u8 },
    #[error("Invalid UTF-8")]
    InvalidUtf8,
    #[error("Length out of range")]
    LengthOutOfRange,
    #[error("Filter nesting too deep")]
    NestingTooDeep,
}

pub type BerResult<T> = Result<T, BerError>;

// Universal tags
pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_ENUMERATED: u8 = 0x0a;
pub const TAG_SEQUENCE: u8 = 0x30; // constructed
pub const TAG_SET: u8 = 0x31;      // constructed

// Encoding

pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

pub fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn encode_integer(n: i64) -> Vec<u8> {
    let bytes: Vec<u8> = if n == 0 {
        vec![0]
    } else {
        let raw = n.to_be_bytes();
        let mut start = 0;
        while start < 7 {
            // Strip leading 0x00 when next byte's high bit is clear
            if raw[start] == 0x00 && raw[start + 1] & 0x80 == 0 {
                start += 1;
            // Strip leading 0xff when next byte's high bit is set
            } else if raw[start] == 0xff && raw[start + 1] & 0x80 != 0 {
                start += 1;
            } else {
                break;
            }
        }
        raw[start..].to_vec()
    };
    encode_tlv(TAG_INTEGER, &bytes)
}

pub fn encode_enumerated(n: u32) -> Vec<u8> {
    let bytes = if n < 0x80 {
        vec![n as u8]
    } else if n < 0x8000 {
        vec![(n >> 8) as u8, n as u8]
    } else {
        vec![(n >> 16) as u8, (n >> 8) as u8, n as u8]
    };
    encode_tlv(TAG_ENUMERATED, &bytes)
}

pub fn encode_octet_string(s: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, s)
}

pub fn encode_string(s: &str) -> Vec<u8> {
    encode_octet_string(s.as_bytes())
}

pub fn encode_set(items: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = items.iter().flatten().copied().collect();
    encode_tlv(TAG_SET, &content)
}

// Decoding

/// Parse a TLV from the start of `buf`.
/// Returns `(tag, value_slice, remaining_slice)`.
pub fn parse_tlv(buf: &[u8]) -> BerResult<(u8, &[u8], &[u8])> {
    if buf.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    let tag = buf[0];
    if tag & 0x1f == 0x1f {
        return Err(BerError::LongFormTag);
    }
    let (len, len_sz) = decode_length(&buf[1..])?;
    let value_start = 1 + len_sz;
    if buf.len() < value_start + len {
        return Err(BerError::UnexpectedEof);
    }
    Ok((tag, &buf[value_start..value_start + len], &buf[value_start + len..]))
}

/// Decode a BER length field from `buf`.
///
/// BER uses two forms:
/// - **Short form** (`buf[0]` bit 7 clear): the length is the byte value itself.
/// - **Long form** (`buf[0]` bit 7 set): the low 7 bits give the number of
///   following bytes that encode the length in big-endian order.
///
/// Returns `(length, bytes_consumed)`.
pub fn decode_length(buf: &[u8]) -> BerResult<(usize, usize)> {
    if buf.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    if buf[0] & 0x80 == 0 {
        return Ok((buf[0] as usize, 1));
    }
    let n = (buf[0] & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err(BerError::LengthOutOfRange);
    }
    if buf.len() < 1 + n {
        return Err(BerError::UnexpectedEof);
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | buf[1 + i] as usize;
    }
    Ok((len, 1 + n))
}

pub fn expect_tag<'a>(
    buf: &'a [u8],
    expected: u8,
) -> BerResult<(&'a [u8], &'a [u8])> {
    let (tag, value, rest) = parse_tlv(buf)?;
    if tag != expected {
        return Err(BerError::UnexpectedTag { expected, got: tag });
    }
    Ok((value, rest))
}

/// Decode a BER INTEGER into an `i64`.
///
/// BER integers are big-endian two's-complement with no redundant leading
/// bytes. The sign is determined by the high bit of the first content byte;
/// we initialise the accumulator to `0` or `-1` so that sign-extension
/// happens naturally as we shift in subsequent bytes.
pub fn decode_integer(buf: &[u8]) -> BerResult<(i64, &[u8])> {
    let (value, rest) = expect_tag(buf, TAG_INTEGER)?;
    if value.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    let mut n = if value[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for b in value {
        n = (n << 8) | *b as i64;
    }
    Ok((n, rest))
}

pub fn decode_enumerated(buf: &[u8]) -> BerResult<(u32, &[u8])> {
    let (value, rest) = expect_tag(buf, TAG_ENUMERATED)?;
    if value.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    let mut n = 0u32;
    for b in value {
        n = (n << 8) | *b as u32;
    }
    Ok((n, rest))
}

pub fn decode_octet_string(buf: &[u8]) -> BerResult<(Vec<u8>, &[u8])> {
    let (value, rest) = expect_tag(buf, TAG_OCTET_STRING)?;
    Ok((value.to_vec(), rest))
}

pub fn decode_string(buf: &[u8]) -> BerResult<(String, &[u8])> {
    let (bytes, rest) = decode_octet_string(buf)?;
    let s = String::from_utf8(bytes).map_err(|_| BerError::InvalidUtf8)?;
    Ok((s, rest))
}

pub fn decode_boolean(buf: &[u8]) -> BerResult<(bool, &[u8])> {
    let (value, rest) = expect_tag(buf, TAG_BOOLEAN)?;
    Ok((!value.is_empty() && value[0] != 0, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integer

    #[test]
    fn integer_roundtrip() {
        for n in [
            0i64, 1, 127, 128, 255, 256, 32767, 32768,
            -1, -128, -129, i32::MAX as i64,
        ] {
            let enc = encode_integer(n);
            let (dec, rest) = decode_integer(&enc).unwrap();
            assert_eq!(dec, n, "roundtrip failed for {n}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn integer_known_encodings() {
        // Single-byte values
        assert_eq!(encode_integer(0), &[0x02, 0x01, 0x00]);
        assert_eq!(encode_integer(1), &[0x02, 0x01, 0x01]);
        assert_eq!(encode_integer(127), &[0x02, 0x01, 0x7f]);
        // Two bytes needed when high bit of first byte would be set
        assert_eq!(encode_integer(128), &[0x02, 0x02, 0x00, 0x80]);
        // Negative
        assert_eq!(encode_integer(-1), &[0x02, 0x01, 0xff]);
        assert_eq!(encode_integer(-128), &[0x02, 0x01, 0x80]);
    }

    // Enumerated

    #[test]
    fn enumerated_roundtrip() {
        for n in [0u32, 1, 49, 80, 127, 128, 255, 256] {
            let enc = encode_enumerated(n);
            let (dec, rest) = decode_enumerated(&enc).unwrap();
            assert_eq!(dec, n);
            assert!(rest.is_empty());
        }
    }

    // Octet string

    #[test]
    fn string_roundtrip() {
        for s in ["", "hello", "uid=alice,ou=people,dc=example,dc=com"] {
            let enc = encode_string(s);
            let (dec, rest) = decode_string(&enc).unwrap();
            assert_eq!(dec, s);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn empty_string_encoding() {
        assert_eq!(encode_string(""), &[0x04, 0x00]);
    }

    // Length encoding

    #[test]
    fn length_short_form() {
        assert_eq!(encode_length(0), &[0x00]);
        assert_eq!(encode_length(1), &[0x01]);
        assert_eq!(encode_length(127), &[0x7f]);
    }

    #[test]
    fn length_long_form() {
        assert_eq!(encode_length(128), &[0x81, 0x80]);
        assert_eq!(encode_length(255), &[0x81, 0xff]);
        assert_eq!(encode_length(256), &[0x82, 0x01, 0x00]);
        assert_eq!(encode_length(65535), &[0x82, 0xff, 0xff]);
    }

    #[test]
    fn length_roundtrip() {
        for len in [0usize, 1, 127, 128, 255, 256, 1000, 65535] {
            let enc = encode_length(len);
            let (dec, consumed) = decode_length(&enc).unwrap();
            assert_eq!(dec, len);
            assert_eq!(consumed, enc.len());
        }
    }

    // TLV

    #[test]
    fn parse_tlv_basic() {
        // OCTET STRING "abc" + trailing garbage
        let buf = [0x04, 0x03, b'a', b'b', b'c', 0xff];
        let (tag, value, rest) = parse_tlv(&buf).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(value, b"abc");
        assert_eq!(rest, &[0xff]);
    }

    #[test]
    fn parse_tlv_empty_value() {
        let buf = [0x04, 0x00];
        let (tag, value, rest) = parse_tlv(&buf).unwrap();
        assert_eq!(tag, 0x04);
        assert!(value.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_tlv_unexpected_eof() {
        assert!(parse_tlv(&[]).is_err());
        // says 3 bytes, only 2 present
        assert!(parse_tlv(&[0x04, 0x03, b'a', b'b']).is_err());
    }

    // Remaining bytes

    #[test]
    fn decode_leaves_remainder() {
        // Two integers concatenated
        let mut buf = encode_integer(42);
        buf.extend(encode_integer(99));
        let (first, rest) = decode_integer(&buf).unwrap();
        let (second, rest2) = decode_integer(rest).unwrap();
        assert_eq!(first, 42);
        assert_eq!(second, 99);
        assert!(rest2.is_empty());
    }
}
