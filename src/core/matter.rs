use std::collections::HashMap;

use lazy_static::lazy_static;

use crate::core::sizage::Sizage;
use crate::error::Error;

#[derive(Debug, Eq, PartialEq)]
pub enum MatterCodex {
    Ed25519Seed,
    Ed25519N,
    X25519,
    Ed25519,
    Blake3_256,
    X25519Private,
    X25519CipherSeed,
    X25519CipherSalt,
    Salt128,
    Ed25519Sig,
}

impl MatterCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            MatterCodex::Ed25519Seed => "A",
            MatterCodex::Ed25519N => "B", // Ed25519 verification key non-transferable, basic derivation.
            MatterCodex::X25519 => "C", // X25519 public encryption key, converted from Ed25519 or Ed25519N.
            MatterCodex::Ed25519 => "D", // Ed25519 verification key basic derivation
            MatterCodex::Blake3_256 => "E", // Blake3 256 bit digest self-addressing derivation.
            MatterCodex::X25519Private => "O", // X25519 private decryption key converted from Ed25519
            MatterCodex::X25519CipherSeed => "P", // X25519 124 char b64 Cipher of 44 char qb64 Seed
            MatterCodex::X25519CipherSalt => "1AAH", // X25519 100 char b64 Cipher of 24 char qb64 Salt
            MatterCodex::Salt128 => "0A", // 128 bit random salt or 128 bit number (see Huge)
            MatterCodex::Ed25519Sig => "0B", // Ed25519 signature.
        }
    }
}

#[derive(Debug)]
pub struct Matter {
    pub raw: Option<Vec<u8>>,
    pub code: &'static str,
    pub qb64b: Option<Vec<u8>>,
    pub qb64: Option<String>,
    pub qb2: Option<Vec<u8>>,
    pub strip: Option<bool>,
}

impl Matter {
    pub fn new(
        raw: Vec<u8>,
        code: &'static str,
        qb64b: Vec<u8>,
        qb64: String,
        qb2: Vec<u8>,
        strip: bool,
    ) -> Matter {
        Self {
            raw: Some(raw),
            code,
            qb64b: Some(qb64b),
            qb64: Some(qb64),
            qb2: Some(qb2),
            strip: Some(strip),
        }
    }
}

impl Default for Matter {
    fn default() -> Self {
        Matter {
            raw: Some(Vec::new()),
            code: MatterCodex::Ed25519N.code(),
            qb64b: Some(Vec::new()),
            qb64: Some("".into()),
            qb2: Some(Vec::new()),
            strip: Some(false),
        }
    }
}

pub trait Size {
    fn size(&self) -> Result<Sizage, Self::Err>;
    type Err;
}

impl Size for MatterCodex {
    fn size(&self) -> Result<Sizage, Self::Err> {
        match self.code() {
            "A" => Ok(Sizage::new(1, 0, 44, 0)),
            "B" => Ok(Sizage::new(1, 0, 44, 0)),
            "C" => Ok(Sizage::new(1, 0, 44, 0)),
            "D" => Ok(Sizage::new(1, 0, 44, 0)),
            "E" => Ok(Sizage::new(1, 0, 44, 0)),
            "O" => Ok(Sizage::new(1, 0, 44, 0)),
            "P" => Ok(Sizage::new(1, 0, 124, 0)),
            "1AAH" => Ok(Sizage::new(2, 0, 24, 0)),
            "0A" => Ok(Sizage::new(1, 0, 88, 0)),
            "0B" => Ok(Sizage::new(4, 0, 100, 0)),
            _ => Err(Error::MatterError("Unknown code".into())),
        }
    }

    type Err = Error;
}

lazy_static! {
    #[rustfmt::skip]
    static ref HARDS: HashMap<char, u16> = [
        ('A', 1), ('B', 1), ('C', 1), ('D', 1), ('E', 1), ('F', 1), ('G', 1),
        ('H', 1), ('I', 1), ('J', 1), ('K', 1), ('L', 1), ('M', 1), ('N', 1), ('O', 1), ('P', 1), ('Q', 1), ('R', 1),
        ('S', 1), ('T', 1), ('U', 1), ('V', 1), ('W', 1), ('X', 1), ('Y', 1), ('Z', 1), ('a', 1), ('b', 1), ('c', 1),
        ('d', 1), ('e', 1), ('f', 1), ('g', 1), ('h', 1), ('i', 1), ('j', 1), ('k', 1), ('l', 1), ('m', 1), ('n', 1),
        ('o', 1), ('p', 1), ('q', 1), ('r', 1), ('s', 1), ('t', 1), ('u', 1), ('v', 1), ('w', 1), ('x', 1), ('y', 1),
        ('z', 1), ('0', 2), ('1', 4), ('2', 4), ('3', 4), ('4', 2), ('5', 2), ('6', 2), ('7', 4), ('8', 4), ('9', 4)
    ].iter().copied().collect();
}

#[cfg(test)]
mod matter_codex_tests {
    use crate::core::matter::{Matter, MatterCodex, Size, HARDS};

    #[test]
    fn test_codes() {
        assert_eq!(MatterCodex::Ed25519Seed.code(), "A");
        assert_eq!(MatterCodex::Ed25519N.code(), "B");
        assert_eq!(MatterCodex::X25519.code(), "C");
        assert_eq!(MatterCodex::Ed25519.code(), "D");
        assert_eq!(MatterCodex::Blake3_256.code(), "E");
        assert_eq!(MatterCodex::X25519Private.code(), "O");
        assert_eq!(MatterCodex::X25519CipherSeed.code(), "P");
        assert_eq!(MatterCodex::X25519CipherSalt.code(), "1AAH");
        assert_eq!(MatterCodex::Salt128.code(), "0A");
        assert_eq!(MatterCodex::Ed25519Sig.code(), "0B");
    }

    #[test]
    fn test_size() {
        let mut s = MatterCodex::Ed25519Seed.size().unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = MatterCodex::Ed25519N.size().unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = MatterCodex::X25519.size().unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = MatterCodex::Ed25519.size().unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = MatterCodex::Blake3_256.size().unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = MatterCodex::X25519Private.size().unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = MatterCodex::X25519CipherSeed.size().unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 124);
        assert_eq!(s.ls, 0);

        s = MatterCodex::X25519CipherSalt.size().unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 24);
        assert_eq!(s.ls, 0);

        s = MatterCodex::Salt128.size().unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = MatterCodex::Ed25519Sig.size().unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 100);
        assert_eq!(s.ls, 0);
    }

    #[test]
    fn test_hards() {
        assert_eq!(HARDS.get(&'A').unwrap(), &1);
        assert_eq!(HARDS.get(&'1').unwrap(), &4);
        assert_eq!(HARDS.get(&'5').unwrap(), &2);
        assert_eq!(HARDS.get(&'7').unwrap(), &4);
    }

    #[test]
    fn test_matter_new() {
        let mut m: Matter = Default::default();
        assert_eq!(m.code, MatterCodex::Ed25519N.code());
        assert_eq!(m.qb64.unwrap(), "");

        // partial override
        m = Matter {
            qb64: Some("qb64".into()),
            ..Default::default()
        };
        assert_eq!(m.qb64.unwrap(), "qb64");

        // full override
        m = Matter {
            raw: Some(b"a".to_vec()),
            code: MatterCodex::X25519CipherSeed.code(),
            qb64b: Some(b"b".to_vec()),
            qb64: Some("qb64".into()),
            qb2: Some(b"c".to_vec()),
            strip: Some(true),
        };

        assert_eq!(m.raw.unwrap(), b"a".to_vec());
        assert_eq!(m.code, MatterCodex::X25519CipherSeed.code());
        assert_eq!(m.qb64b.unwrap(), b"b".to_vec());
        assert_eq!(m.qb64.unwrap(), "qb64");
        assert_eq!(m.qb2.unwrap(), b"c".to_vec());
        assert_eq!(m.strip.unwrap(), true);
    }
}
