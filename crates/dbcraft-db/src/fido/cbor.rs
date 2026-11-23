//! The part of CBOR (RFC 8949) that CTAP2 uses: integers, byte and text
//! strings, arrays, maps and booleans, definite lengths only. Requests are
//! built with their map keys in CTAP2's canonical order.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed CBOR: {}", self.0)
    }
}

/// Deeper than any CTAP2 response nests.
const MAX_DEPTH: usize = 16;

impl Value {
    pub fn text(text: &str) -> Self {
        Self::Text(text.to_owned())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Int(n) if *n >= 0 => head(out, 0, n.unsigned_abs()),
            // -1 - n, as major type 1 stores it.
            Self::Int(n) => head(out, 1, (-1 - n) as u64),
            Self::Bytes(bytes) => {
                head(out, 2, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
            Self::Text(text) => {
                head(out, 3, text.len() as u64);
                out.extend_from_slice(text.as_bytes());
            }
            Self::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out);
                }
            }
            Self::Map(entries) => {
                head(out, 5, entries.len() as u64);
                for (key, value) in entries {
                    key.encode_into(out);
                    value.encode_into(out);
                }
            }
            Self::Bool(false) => out.push(0xf4),
            Self::Bool(true) => out.push(0xf5),
            Self::Null => out.push(0xf6),
        }
    }

    /// One value that takes all of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader { bytes, at: 0 };
        let value = reader.value(0)?;
        if reader.at != bytes.len() {
            return Err(Error("bytes after the value"));
        }
        Ok(value)
    }

    /// The value of a map's integer `key`.
    pub fn get(&self, key: i64) -> Option<&Value> {
        self.entry(|k| *k == Value::Int(key))
    }

    /// The value of a map's text `key`.
    #[cfg(test)]
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        self.entry(|k| matches!(k, Value::Text(t) if t == key))
    }

    fn entry(&self, matches: impl Fn(&Value) -> bool) -> Option<&Value> {
        match self {
            Self::Map(entries) => entries.iter().find(|(k, _)| matches(k)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// A major type with its argument, in the shortest form.
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    if n < 24 {
        out.push(major | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[major | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(major | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(major | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Error("truncated"))?;
        let taken = &self.bytes[self.at..end];
        self.at = end;
        Ok(taken)
    }

    fn argument(&mut self, info: u8) -> Result<u64, Error> {
        Ok(match info {
            0..24 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().expect("2 bytes"),
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("4 bytes"),
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")),
            _ => return Err(Error("indefinite length or reserved argument")),
        })
    }

    /// A length, bounded by what is left: each item takes a byte at least.
    fn length(&mut self, info: u8) -> Result<usize, Error> {
        let n = self.argument(info)?;
        usize::try_from(n)
            .ok()
            .filter(|n| *n <= self.bytes.len() - self.at)
            .ok_or(Error("length beyond the data"))
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error("nested too deep"));
        }
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        Ok(match major {
            0 => Value::Int(
                i64::try_from(self.argument(info)?).map_err(|_| Error("integer too large"))?,
            ),
            1 => {
                let n =
                    i64::try_from(self.argument(info)?).map_err(|_| Error("integer too small"))?;
                Value::Int(-1 - n)
            }
            2 => {
                let n = self.length(info)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.length(info)?;
                let text = std::str::from_utf8(self.take(n)?).map_err(|_| Error("bad UTF-8"))?;
                Value::Text(text.to_owned())
            }
            4 => {
                let n = self.length(info)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let n = self.length(info)?;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    let key = self.value(depth + 1)?;
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Value::Map(entries)
            }
            // A tag: CTAP2 doesn't use them, the value counts.
            6 => {
                self.argument(info)?;
                self.value(depth + 1)?
            }
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 | 23 => Value::Null,
                _ => return Err(Error("floats and other simple values")),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let value = Value::Map(vec![
            (Value::Int(1), Value::text("ssh:")),
            (Value::Int(2), Value::Bytes(vec![7; 32])),
            (
                Value::Int(3),
                Value::Array(vec![Value::Map(vec![
                    (Value::text("id"), Value::Bytes(vec![1; 300])),
                    (Value::text("type"), Value::text("public-key")),
                ])]),
            ),
            (Value::Int(-25), Value::Bool(true)),
            (Value::Int(70_000), Value::Int(-70_000)),
            (Value::Int(i64::MAX), Value::Int(i64::MIN)),
            (Value::Null, Value::Bool(false)),
        ]);
        assert_eq!(Value::decode(&value.encode()).unwrap(), value);
    }

    #[test]
    fn known_encodings() {
        // RFC 8949, appendix A.
        assert_eq!(Value::Int(0).encode(), [0x00]);
        assert_eq!(Value::Int(23).encode(), [0x17]);
        assert_eq!(Value::Int(24).encode(), [0x18, 0x18]);
        assert_eq!(Value::Int(1000).encode(), [0x19, 0x03, 0xe8]);
        assert_eq!(Value::Int(-1).encode(), [0x20]);
        assert_eq!(Value::Int(-25).encode(), [0x38, 0x18]);
        assert_eq!(Value::Int(-1000).encode(), [0x39, 0x03, 0xe7]);
        assert_eq!(Value::text("IETF").encode(), b"\x64IETF");
        assert_eq!(Value::Bool(true).encode(), [0xf5]);
    }

    #[test]
    fn malformed() {
        for bytes in [
            &[][..],
            &[0x18],                                                 // argument missing
            &[0x42, 0x01],                                           // bytes cut short
            &[0x5f, 0x01, 0xff],                                     // indefinite length
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // huge array
            &[0x62, 0xff, 0xfe],                                     // not UTF-8
            &[0xf9, 0x3c, 0x00],                                     // a float
            &[0x01, 0x02],                                           // bytes after the value
            &[0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0],                      // beyond i64
        ] {
            assert!(Value::decode(bytes).is_err(), "{bytes:02x?}");
        }
        let deep = [vec![0x81; 40], vec![0x00]].concat();
        assert!(Value::decode(&deep).is_err());
    }
}
