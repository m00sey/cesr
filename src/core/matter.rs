use crate::error::Error;
use crate::core::sizage::Sizage;

#[derive(Debug)]
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
            MatterCodex::Ed25519N => "B",    // Ed25519 verification key non-transferable, basic derivation.
            MatterCodex::X25519 => "C",    // X25519 public encryption key, converted from Ed25519 or Ed25519N.
            MatterCodex::Ed25519 => "D",    // Ed25519 verification key basic derivation
            MatterCodex::Blake3_256 => "E",    // Blake3 256 bit digest self-addressing derivation.
            MatterCodex::X25519Private => "O",    // X25519 private decryption key converted from Ed25519
            MatterCodex::X25519CipherSeed => "P",    // X25519 124 char b64 Cipher of 44 char qb64 Seed
            MatterCodex::X25519CipherSalt => "1AAH", // X25519 100 char b64 Cipher of 24 char qb64 Salt
            MatterCodex::Salt128 => "0A",   // 128 bit random salt or 128 bit number (see Huge)
            MatterCodex::Ed25519Sig => "0B",   // Ed25519 signature.
        }
    }
}

pub struct Matter {
    pub raw: Option<Vec<u8>>,
    pub code: Option<String>,
    pub qb64b: Option<Vec<u8>>,
    pub qb64: Option<String>,
    pub qb2: Option<Vec<u8>>,
    pub strip: Option<bool>,
}

impl Matter {
    pub fn new() -> Matter {
        Self {
            raw: None,
            code: None,
            qb64b: None,
            qb64: None,
            qb2: None,
            strip: None,
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

#[cfg(test)]
mod matter_codex_tests {
    use crate::core::matter::{MatterCodex, Size};

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
}