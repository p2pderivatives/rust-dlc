use bitcoin::secp256k1::key::PublicKey;

pub fn to_vec(hex: &str) -> Option<Vec<u8>> {
	let len = hex.len() / 2;
	let mut out = Vec::with_capacity(hex.len() / 2);
	out.resize(len, 0);

	match to_slice(hex, &mut out) {
		Err(_) => None,
		Ok(_) => Some(out),
	}
}

pub fn to_slice(hex: &str, arr: &mut [u8]) -> Result<(), ()> {
	let mut b = 0;
	for (idx, c) in hex.as_bytes().iter().enumerate() {
		b <<= 4;
		match *c {
			b'A'..=b'F' => b |= c - b'A' + 10,
			b'a'..=b'f' => b |= c - b'a' + 10,
			b'0'..=b'9' => b |= c - b'0',
			_ => return Err(()),
		}
		if (idx & 1) == 1 {
			arr[idx / 2] = b;
			b = 0;
		}
	}

	return Ok(());
}

#[inline]
pub fn hex_str(value: &[u8]) -> String {
	let mut res = String::with_capacity(64);
	for v in value {
		res += &format!("{:02x}", v);
	}
	res
}

pub fn to_compressed_pubkey(hex: &str) -> Option<PublicKey> {
	let data = match to_vec(&hex[0..33 * 2]) {
		Some(bytes) => bytes,
		None => return None,
	};
	match PublicKey::from_slice(&data) {
		Ok(pk) => Some(pk),
		Err(_) => None,
	}
}
