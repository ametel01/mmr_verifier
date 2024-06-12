use core::array::ArrayTrait;
// The following code was taken from the Alexandria library and added as internal library to 
// make auditing easier. The original code can be found at https://github.com/keep-starknet-strange/alexandria/blob/main/src/math/src/keccak256.cairo

use core::integer::u128_byte_reverse;
use core::integer::u32_safe_divmod;
use keccak::cairo_keccak;
use alexandria_math::BitShift;

#[generate_trait]
impl U64Impl of U64Trait {
    /// Converts a little-endian byte slice to a 64-bit unsigned integer
    ///
    /// # Arguments
    ///
    /// * `self` - A `Span<u8>` slice of size n <=8.
    ///
    /// # Returns
    ///
    /// A tuple containing the converted 64-bit unsigned integer and the amount of bytes consumed
    fn from_le_bytes(mut self: Span<u8>) -> (u64, u32) {
        assert(self.len() < 9, 'bytes dont fit in u64');
        // Pack full value
        let mut value: u64 = 0;
        let n_bytes: u32 = self.len();
        loop {
            let byte = match self.pop_back() {
                Option::Some(byte) => *byte,
                Option::None => { break; },
            };
            value = value * 0x100 + (byte.into());
        };
        (value, n_bytes)
    }
}

/// Reverse the endianness of an u256
fn reverse_endianness(value: u256) -> u256 {
    let new_low = u128_byte_reverse(value.high);
    let new_high = u128_byte_reverse(value.low);
    u256 { low: new_low, high: new_high }
}

/// Computes the Solidity-compatible Keccak hash of an array of bytes.
///
/// # Arguments
///
/// * `self` - A `Array<u8>` of bytes.
///
/// # Returns
///
/// A `u256` value representing the Keccak hash of the input bytes array.
pub fn hash(mut self: Span<u8>) -> u256 {
    // Converts byte array to little endian 8 byte words array.
    let mut words64: Array<u64> = Default::default();
    while self
        .len() >= 8 {
            let current_word = self.slice(0, 8);
            let (value, _) = U64Trait::from_le_bytes(current_word);
            words64.append(value);
            self = self.slice(8, self.len() - 8);
        };
    // handle last word specifically 
    let (last_word, last_word_bytes) = U64Trait::from_le_bytes(self);
    reverse_endianness(cairo_keccak(ref words64, last_word, last_word_bytes))
}

pub fn hash_2(a: u256, b: u256) -> u256 {
    let a_array = u256_to_big_endian_bytes(a);
    let b_array = u256_to_big_endian_bytes(b);
    let mut combined = array![];
    let mut i = 0;
    while i < a_array.len() {
        combined.append(*a_array.at(i));
        i += 1;
    };
    i = 0;
    while i < b_array.len() {
        combined.append(*b_array.at(i));
        i += 1;
    };
    hash(combined.span())
}

pub fn u64_to_u8_array(input: Span<u64>, len_bytes: usize) -> Array<u8> {
    let mut bytes: Array<u8> = array![];
    let (full_words, remainder) = u32_safe_divmod(len_bytes, 8);

    let mut i = 0;
    while (i < full_words) {
        let value = *input.at(i);
        let input_bytes = u64_to_big_endian_bytes(value, 8);
        let len = input_bytes.len();
        let mut j = 0;
        while (j < len) {
            bytes.append(*input_bytes.at(j));
            j += 1;
        };
        i += 1;
    };

    if remainder > 0 {
        let value = *input.at(full_words);
        let input_bytes = u64_to_big_endian_bytes(value, remainder);
        let len = input_bytes.len();
        let mut j = 0;
        while (j < len) {
            bytes.append(*input_bytes.at(j));
            j += 1;
        };
    }

    bytes
}

/// Converts a 64-bit unsigned integer into big-endian byte slice.
///
/// # Arguments
/// * `num` - A 64-bit unsigned integer to be converted.
/// * `len` - The length of the output byte array.
///
/// # Returns
/// * `Array<u8>` - The resulting byte array.
fn u64_to_big_endian_bytes(num: u64, len: u32) -> Array<u8> {
    let mut out = array![];

    let mut i = 0_u32;
    while (i < len) {
        let byte: u8 = (BitShift::shr(num, ((len - 1 - i) * 8).into()) & 0xFF).try_into().unwrap();
        out.append(byte);
        i += 1;
    };

    out
}

pub fn u256_to_big_endian_bytes(num: u256) -> Array<u8> {
    let mut out = array![];

    let mut i = 0_u32;
    while (i < 32) {
        let byte: u8 = (BitShift::shr(num, ((31 - i) * 8).into()) & 0xFF).try_into().unwrap();
        out.append(byte);
        i += 1;
    };

    out
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_hash_2() {
        let a = 0xfaaf4b2eab3e6d85ae70ce68cf0aa7ea5a20663f3dbeea51e78e413891c036b7;
        let b = 0xe26f004f277937b0178c6d905c8d70c8319fc809f83c6d3b3663b544742fa93e;

        let res = super::hash_2(a, b);

        let exp = 0x80958759fd9430e4aa93fa159a338ad6f6e6a5047aea3185c7cc0ca4d9e2ddc6;
        assert_eq!(res, exp);
    }


    #[test]
    fn test_u256_to_big_endian_bytes() {
        let num = 0xe9116a7c5bccd54363a276ad34ac7596a9d81acc1945e3b6422114b0d9c9091e;
        let expected = array![
            233,
            17,
            106,
            124,
            91,
            204,
            213,
            67,
            99,
            162,
            118,
            173,
            52,
            172,
            117,
            150,
            169,
            216,
            26,
            204,
            25,
            69,
            227,
            182,
            66,
            33,
            20,
            176,
            217,
            201,
            9,
            30
        ];
        let result = super::u256_to_big_endian_bytes(num);
        assert_eq!(result, expected);
    }
}
