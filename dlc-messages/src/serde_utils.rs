pub fn serialize_hex<S>(hex: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if s.is_human_readable() {
        let string = hex.iter().fold(String::new(), |mut s, e| {
            s.push_str(&format!("{:02x}", e));
            s
        });
        assert!(string.len() % 2 == 0);
        s.serialize_str(&string)
    } else {
        s.serialize_bytes(hex)
    }
}

pub fn deserialize_hex_array<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let string: String = serde::de::Deserialize::deserialize(deserializer)?;
        let mut hex = [0u8; 32];
        from_hex(&string, &mut hex).map_err(serde::de::Error::custom)?;
        Ok(hex)
    } else {
        serde::de::Deserialize::deserialize(deserializer)
    }
}

pub fn deserialize_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let string: String = serde::de::Deserialize::deserialize(deserializer)?;
        let mut hex = Vec::with_capacity(string.len() / 2);
        hex.resize(string.len() / 2, 0);
        from_hex(&string, &mut hex).map_err(serde::de::Error::custom)?;
        Ok(hex)
    } else {
        serde::de::Deserialize::deserialize(deserializer)
    }
}

fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, String> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err("Invalid hex length".to_string());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return Err("Invalid hex character".to_string()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}
