//! Lossless, injective encoding of sandbox labels as Kubernetes label values.
//!
//! A Kubernetes label value is at most 63 characters, may be empty, and
//! otherwise begins and ends alphanumeric with only `-`, `_`, `.` and
//! alphanumerics between. Petri's `petri.workspace` value is
//! `<run id>/<workspace id>`, and a `/` is not allowed.
//!
//! A value that is already valid and contains no `_` is carried verbatim.
//! Any other value is escaped: every byte outside `[A-Za-z0-9.-]` becomes
//! `_` plus two lowercase hex digits, and a literal `_` becomes `__`, with a
//! leading `x_` marker so an escaped value can never collide with a verbatim
//! one. The encoding is reversible and injective, so exact-match selection
//! on an encoded value can never pick the wrong sandbox. An encoded value
//! longer than 63 characters is refused, never truncated.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The longest label value Kubernetes accepts.
pub const MAX_LABEL_VALUE: usize = 63;
const ESCAPED_PREFIX: &str = "x_";

/// Whether `value` is a valid Kubernetes label value.
pub fn is_valid_label_value(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() <= MAX_LABEL_VALUE
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Whether `key` is a valid Kubernetes label key: an optional DNS-subdomain
/// prefix and `/`, then a name segment of at most 63 characters.
pub fn is_valid_label_key(key: &str) -> bool {
    let (prefix, name) = match key.rsplit_once('/') {
        Some((prefix, name)) => (Some(prefix), name),
        None => (None, key),
    };
    let name_ok = !name.is_empty() && is_valid_label_value(name);
    let prefix_ok = prefix.is_none_or(|prefix| {
        !prefix.is_empty()
            && prefix.len() <= 253
            && prefix.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && !part.starts_with('-')
                    && !part.ends_with('-')
            })
    });
    name_ok && prefix_ok
}

/// Encodes `value` as a label value, or returns why it cannot be carried.
pub fn encode_label_value(value: &str) -> Result<String, String> {
    if is_valid_label_value(value) && !value.contains('_') && !value.starts_with(ESCAPED_PREFIX) {
        return Ok(value.to_owned());
    }
    let mut encoded = String::from(ESCAPED_PREFIX);
    let last = value.len().saturating_sub(1);
    for (index, byte) in value.bytes().enumerate() {
        // The final byte must render alphanumeric-terminated, so a trailing
        // `_`, `-` or `.` is always hex-escaped (`_5f`, `_2d`, `_2e`).
        let must_hex = index == last && !byte.is_ascii_alphanumeric();
        match byte {
            b'_' if !must_hex => encoded.push_str("__"),
            b if !must_hex && (b.is_ascii_alphanumeric() || b == b'-' || b == b'.') => {
                encoded.push(char::from(b));
            }
            b => {
                let _ = write!(encoded, "_{b:02x}");
            }
        }
    }
    if encoded.len() > MAX_LABEL_VALUE {
        return Err(format!(
            "label value {value:?} encodes to {} characters, over the Kubernetes limit of \
             {MAX_LABEL_VALUE}; refusing rather than truncating a reconcile key",
            encoded.len()
        ));
    }
    Ok(encoded)
}

/// Reverses [`encode_label_value`].
pub fn decode_label_value(encoded: &str) -> Option<String> {
    let Some(body) = encoded.strip_prefix(ESCAPED_PREFIX) else {
        return Some(encoded.to_owned());
    };
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'_' {
            if bytes.get(index + 1) == Some(&b'_') {
                out.push(b'_');
                index += 2;
            } else {
                let hex = body.get(index + 1..index + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Encodes a whole label map, refusing an invalid key or an over-long value.
pub(crate) fn encode_labels(
    labels: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    labels
        .iter()
        .map(|(key, value)| {
            if !is_valid_label_key(key) {
                return Err(format!(
                    "label key {key:?} is not a valid Kubernetes label key"
                ));
            }
            Ok((key.clone(), encode_label_value(value)?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn petri_workspace_round_trips_and_is_a_valid_value() {
        let value = "01JABCDEFGHJKMNPQRSTVWXYZ0/implement";
        let encoded = encode_label_value(value).expect("fits");
        assert!(is_valid_label_value(&encoded), "{encoded}");
        assert_eq!(decode_label_value(&encoded).as_deref(), Some(value));
    }

    #[test]
    fn verbatim_values_pass_through() {
        for value in ["01JABCDEFGHJKMNPQRSTVWXYZ0", "7", "", "a.b-c"] {
            assert_eq!(encode_label_value(value).as_deref(), Ok(value));
            assert_eq!(decode_label_value(value).as_deref(), Some(value));
        }
    }

    #[test]
    fn encoding_is_injective_across_tricky_inputs() {
        let values = [
            "a/b", "a_2fb", "x_a", "a_b", "a__b", "_", "a.", "-a", "x_", "a b", "é",
        ];
        let mut seen = std::collections::BTreeSet::new();
        for value in values {
            let encoded = encode_label_value(value).expect("fits");
            assert!(is_valid_label_value(&encoded), "{value:?} -> {encoded:?}");
            assert_eq!(
                decode_label_value(&encoded).as_deref(),
                Some(value),
                "{encoded}"
            );
            assert!(seen.insert(encoded.clone()), "collision on {encoded}");
        }
    }

    #[test]
    fn an_over_long_value_is_refused_not_truncated() {
        let value = format!("01JABCDEFGHJKMNPQRSTVWXYZ0/{}", "w".repeat(40));
        let error = encode_label_value(&value).expect_err("too long");
        assert!(error.contains("refusing"), "{error}");
    }

    #[test]
    fn keys_are_validated() {
        assert!(is_valid_label_key("petri.workspace"));
        assert!(is_valid_label_key("app.kubernetes.io/managed-by"));
        assert!(!is_valid_label_key("bad key"));
        assert!(!is_valid_label_key("Upper.Case/x"));
    }
}
