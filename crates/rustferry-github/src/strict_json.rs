//! Bounded JSON decoding that rejects duplicate object keys and trailing data.

use serde::{Deserialize, Deserializer, de};
use serde_json::Value;

/// Secret-free strict JSON failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictJsonError {
    Empty,
    TooLarge,
    Invalid,
}

pub(crate) fn decode<T: de::DeserializeOwned>(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<T, StrictJsonError> {
    if bytes.is_empty() {
        return Err(StrictJsonError::Empty);
    }
    if bytes.len() > maximum_bytes {
        return Err(StrictJsonError::TooLarge);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value =
        UniqueJsonValue::deserialize(&mut deserializer).map_err(|_| StrictJsonError::Invalid)?;
    deserializer.end().map_err(|_| StrictJsonError::Invalid)?;
    serde_json::from_value(value.0).map_err(|_| StrictJsonError::Invalid)
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> de::Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value::<UniqueJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        value: u64,
    }

    #[test]
    fn accepts_one_complete_unique_document() {
        assert_eq!(
            decode::<Fixture>(br#"{"value":7}"#, 64),
            Ok(Fixture { value: 7 })
        );
    }

    #[test]
    fn rejects_duplicate_keys_trailing_data_and_bounds() {
        assert_eq!(
            decode::<Fixture>(br#"{"value":7,"value":8}"#, 64),
            Err(StrictJsonError::Invalid)
        );
        assert_eq!(
            decode::<Fixture>(br#"{"value":7} null"#, 64),
            Err(StrictJsonError::Invalid)
        );
        assert_eq!(decode::<Fixture>(b"", 64), Err(StrictJsonError::Empty));
        assert_eq!(
            decode::<Fixture>(br#"{"value":7}"#, 2),
            Err(StrictJsonError::TooLarge)
        );
    }
}
