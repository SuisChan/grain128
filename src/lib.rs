use std::convert::TryInto;

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct Grain128 {
    LFSR: [u8; 128],
    NFSR: [u8; 128],

    key: [u8; 16],
    keysize: usize,
    ivsize: usize,
}

impl Grain128 {
    pub fn keysetup(key: &[u8], keysize: usize, ivsize: usize) -> Self {
        Self {
            key: key.try_into().unwrap(),
            keysize,
            ivsize,
            LFSR: [0u8; 128],
            NFSR: [0u8; 128],
        }
    }

    /// Load the key and perform initial clockings.
    ///
    ///  Assumptions
    /// * The key is 16 bytes and the IV is 12 bytes. The registers are loaded in the following way:
    /// * NFSR[0] = lsb of key[0]
    /// * ...
    /// * NFSR[7] = msb of key[0]
    /// * ...
    /// * NFSR[120] = lsb of key[16]
    /// * ...
    /// * NFSR[127] = msb of key[16]
    /// * LFSR[0] = lsb of IV[0]
    /// * ...
    /// * LFSR[7] = msb of IV[0]
    /// * ...
    /// * LFSR[88] = lsb of IV[12]
    /// * ...
    /// * LFSR[95] = msb of IV[12]
    pub fn ivsetup(&mut self, iv: &[u8]) {
        for i in 0..(self.ivsize / 8) {
            for j in 0..8 {
                self.NFSR[i * 8 + j] = (self.key[i] >> j) & 1;
                self.LFSR[i * 8 + j] = (iv[i] >> j) & 1;
            }
        }

        for i in self.ivsize / 8..self.keysize / 8 {
            for j in 0..8 {
                self.NFSR[i * 8 + j] = (self.key[i] >> j) & 1;
                self.LFSR[i * 8 + j] = 1;
            }
        }

        /* do initial clockings */
        for _ in 0..256 {
            let outbit = self.keystream();
            self.LFSR[127] ^= outbit;
            self.NFSR[127] ^= outbit;
        }
    }

    /// Generates a new bit and updates the internal state of the cipher.
    fn keystream(&mut self) -> u8 {
        /* Calculate feedback and output bits */
        let outbit = self.NFSR[2]
            ^ self.NFSR[15]
            ^ self.NFSR[36]
            ^ self.NFSR[45]
            ^ self.NFSR[64]
            ^ self.NFSR[73]
            ^ self.NFSR[89]
            ^ self.LFSR[93]
            ^ (self.NFSR[12] & self.LFSR[8])
            ^ (self.LFSR[13] & self.LFSR[20])
            ^ (self.NFSR[95] & self.LFSR[42])
            ^ (self.LFSR[60] & self.LFSR[79])
            ^ (self.NFSR[12] & self.NFSR[95] & self.LFSR[95]);

        let n_bit = self.LFSR[0]
            ^ self.NFSR[0]
            ^ self.NFSR[26]
            ^ self.NFSR[56]
            ^ self.NFSR[91]
            ^ self.NFSR[96]
            ^ (self.NFSR[3] & self.NFSR[67])
            ^ (self.NFSR[11] & self.NFSR[13])
            ^ (self.NFSR[17] & self.NFSR[18])
            ^ (self.NFSR[27] & self.NFSR[59])
            ^ (self.NFSR[40] & self.NFSR[48])
            ^ (self.NFSR[61] & self.NFSR[65])
            ^ (self.NFSR[68] & self.NFSR[84]);

        let l_bit = self.LFSR[0]
            ^ self.LFSR[7]
            ^ self.LFSR[38]
            ^ self.LFSR[70]
            ^ self.LFSR[81]
            ^ self.LFSR[96];

        /* Update registers */
        for i in 1..self.keysize {
            self.NFSR[i - 1] = self.NFSR[i];
            self.LFSR[i - 1] = self.LFSR[i];
        }

        self.NFSR[(self.keysize) - 1] = n_bit;
        self.LFSR[(self.keysize) - 1] = l_bit;
        return outbit;
    }

    /// Generate keystream in bytes
    ///
    /// Assumptions
    /// * Bits are generated in order z0, z1, z2...
    ///
    /// The bits are stored in a byte in order:
    /// * lsb of keystream[0] = z0
    /// * ...
    /// * msb of keystream[0] = z7
    /// * ...
    /// * lsb of keystream[1] = z8
    /// * ...
    /// * msb of keystream[1] = z15
    /// * ...
    /// * ...
    pub fn keystream_bytes(&mut self, keystream: &mut [u8]) {
        for i in 0..keystream.len() {
            keystream[i] = 0;

            for j in 0..8 {
                keystream[i] |= self.keystream() << j;
            }
        }
    }

    pub fn encrypt_bytes(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        for i in 0..plaintext.len() {
            let mut k = 0;

            for j in 0..8 {
                k |= self.keystream() << j;
            }
            ciphertext[i] = plaintext[i] ^ k;
        }
    }

    pub fn decrypt_bytes(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        for i in 0..ciphertext.len() {
            let mut k = 0;

            for j in 0..8 {
                k |= self.keystream() << j;
            }
            plaintext[i] = ciphertext[i] ^ k;
        }
    }
}

#[cfg(test)]
#[macro_use]
extern crate hex_literal;
mod tests {
    #[test]
    fn testvectors() {
        let tt = vec![
            (
                hex!("00000000000000000000000000000000"),
                hex!("f09b7bf7d7f6b5c2de2ffc73ac21397f"),
                hex!("000000000000000000000000"),
            ),
            (
                hex!("0123456789abcdef123456789abcdef0"),
                hex!("afb5babfa8de896b4b9c6acaf7c4fbfd"),
                hex!("0123456789abcdef12345678"),
            ),
        ];

        for (key, expect, iv) in tt.iter() {
            let mut g = crate::Grain128::keysetup(key.as_ref(), 128, 96);
            g.ivsetup(iv.as_ref());

            let mut ciphertext = [0u8; 16];
            g.keystream_bytes(&mut ciphertext);

            assert_eq!(ciphertext.as_ref(), expect);
        }
    }

    #[test]
    fn encrypt_test() {
        let test = vec![
            (
                hex!("d95ebe3562cadd429867b8cc7cd7b7e8"),
                hex!("60b178b8e203df01d08ad1f38be25c82"),
                hex!("00000000000000000000000000000000"),
            ),
            (
                hex!("831fad16a6bebb9d305eb82c680b88f2"),
                hex!("6ab6530a69c187dd6131f1432530260c"),
                hex!("00000000000000000000000000000000"),
            ),
            (
                hex!("5146d270d4014fe53a203050cf0acb53"),
                hex!("95518e0d71badcedff6632e19366dbca"),
                hex!("505b968998ed76050d0b9ac884043e0d"),
            ),
            (
                hex!("ffb202f567b27327c33d4c179510d03f"),
                hex!("f0b4c6480ab7aede6f623b40f11bf983"),
                hex!("4f9e44aa744945f2656ffb159f567f61"),
            ),
            (
                hex!("fbdc92620a074e89ae08b39f88d89c0c"),
                hex!("11f93bf57bc33e80a8eeaf4024792c7d"),
                hex!("00000000000000000000000000000000"),
            ),
        ];

        for (key, expect, plaintext) in test.iter() {
            let mut g = crate::Grain128::keysetup(key.as_ref(), 128, 128);
            g.ivsetup(vec![0u8; 16].as_ref());

            let mut ciphertext = [0u8; 16];
            g.encrypt_bytes(plaintext, &mut ciphertext);

            assert_eq!(ciphertext.as_ref(), expect);
        }
    }
}