use core::array::SpanTrait;
use core::poseidon::poseidon_hash_span;
use alexandria_math::BitShift;
use mmr_verifier::keccak;

#[derive(Drop)]
struct Proof {
    element_index: usize,
    element_hash: u256,
    siblings: Span<u256>,
    peaks: Span<u256>,
    elements_count: usize,
}

fn verify_proof(element_value: u256, proof: Proof) -> Result<bool, felt252> {
    let leaf_count = mmr_size_to_leaf_count(proof.elements_count);
    let peaks_count = leaf_count_to_peaks_count(leaf_count);

    if peaks_count != proof.peaks.len() {
        return Result::Err('Invalid peaks count');
    }

    let element_index = proof.element_index;

    if element_index == 0 {
        return Result::Err('Invalid element index');
    }

    if element_index >= proof.elements_count {
        return Result::Err('Invalid element index');
    }

    let (peak_index, peak_height) = get_peak_info(proof.elements_count, element_index);

    if proof.siblings.len() != peak_height {
        return Result::Ok(false);
    }

    let mut hash = element_value;
    let mut leaf_index = element_index_to_leaf_index(element_index).unwrap();

    let sibling_len = proof.siblings.len();
    let mut i = 0;

    while i < sibling_len {
        let is_right_child = leaf_index % 2 == 1;
        leaf_index /= 2;

        if is_right_child {
            hash = keccak::hash_2(*proof.siblings.at(i), hash);
        } else {
            hash = keccak::hash_2(hash, *proof.siblings.at(i));
        }
        i += 1;
    };

    Result::Ok(hash == *proof.peaks.at(peak_index))
}

fn mmr_size_to_leaf_count(size: usize) -> usize {
    let mut remaining_size = size;
    let bits = bit_length(remaining_size + 1);
    let mut mountain_tips = BitShift::shl(1, bits - 1);
    let mut leaf_count = 0;

    while mountain_tips > 0 {
        let mountain_size = 2 * mountain_tips - 1;
        if mountain_size <= remaining_size {
            remaining_size -= mountain_size;
            leaf_count += mountain_tips;
        }
        mountain_tips = BitShift::shr(mountain_tips, 1);
    };
    leaf_count
}

fn leaf_count_to_peaks_count(leaf_count: usize) -> usize {
    count_ones(leaf_count)
}

fn count_ones(mut value: usize) -> usize {
    let mut ones_count = 0;
    while value > 0 {
        value = value & (value - 1);
        ones_count += 1;
    };
    ones_count
}

fn get_peak_info(mut elements_count: usize, mut element_index: usize) -> (usize, usize) {
    let mut mountain_height = bit_length(elements_count);
    let mut mountain_elements_count = BitShift::shl(1, mountain_height) - 1;
    let mut mountain_index = 0;
    let mut result = (0, 0);

    loop {
        if mountain_elements_count <= elements_count {
            if element_index <= mountain_elements_count {
                result = (mountain_index, mountain_height - 1);
                break;
            }
            elements_count -= mountain_elements_count;
            element_index -= mountain_elements_count;
            mountain_index += 1;
        }
        mountain_elements_count = BitShift::shr(mountain_elements_count, 1);
        mountain_height -= 1;
    };
    result
}

fn element_index_to_leaf_index(element_index: usize) -> Result<usize, felt252> {
    if element_index == 0 {
        panic!("Invalid element index");
    }
    elements_count_to_leaf_count(element_index - 1)
}

fn elements_count_to_leaf_count(elements_count: usize) -> Result<usize, felt252> {
    let mut leaf_count = 0;
    let mut mountain_leaf_count = BitShift::shl(1, bit_length(elements_count));
    let mut current_elements_count = elements_count;

    while mountain_leaf_count > 0 {
        let mountain_elements_count = 2 * mountain_leaf_count - 1;
        if mountain_elements_count <= current_elements_count {
            leaf_count += mountain_leaf_count;
            current_elements_count -= mountain_elements_count;
        }
        mountain_leaf_count = BitShift::shr(mountain_leaf_count, 1);
    };

    if current_elements_count > 0 {
        return Result::Err('Invalid elements count');
    } else {
        return Result::Ok(leaf_count);
    }
}

fn retrieve_peaks_hashes(peak_idxs: Span<u256>) -> Result<Array<u256>, felt252> {
    Result::Ok(array![])
}

fn find_peaks(mut elements_count: usize) -> Array<usize> {
    let mut mountain_elements_count = (BitShift::shl(1, bit_length(elements_count))) - 1;
    let mut mountain_index_shift = 0;
    let mut peaks: Array<usize> = array![];

    while mountain_elements_count > 0 {
        if mountain_elements_count <= elements_count {
            mountain_index_shift += mountain_elements_count;
            peaks.append(mountain_index_shift);
            elements_count -= mountain_elements_count;
        }
        mountain_elements_count = BitShift::shr(mountain_elements_count, 1);
    };

    if elements_count > 0 {
        return array![];
    }

    peaks
}


fn bit_length(num: usize) -> usize {
    if num == 0 {
        return 0;
    }

    let mut bit_position = 0;
    let mut curr_n = 1;
    while num >= curr_n {
        bit_position += 1;
        curr_n = BitShift::shl(curr_n, 1);
    };
    bit_position
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_verify_proof() {
        let proof = super::proof_1();
        let res = super::verify_proof(proof.element_hash, proof,);
        assert_eq!(res, Result::Ok(true));

        let proof = super::proof_2();
        let res = super::verify_proof(proof.element_hash, proof,);
        assert_eq!(res, Result::Ok(true));
    }
}

fn proof_1() -> Proof {
    Proof {
        element_index: 191,
        element_hash: 0x799c04bffdee59cbe1f71aabb5dd6b50f2330c2343812dd30cf21bd5f96be982,
        siblings: array![
            0x648d7eea42b054baf0d9b1083bb1680013d18435de35e528989a629d14716234,
            0x7039ad4f2e886e64bd9ab58af5e9645bf4dce4f19d08bb9c7037433e61686a19,
        ]
            .span(),
        peaks: array![
            0xe9bc1501c1b36bdef0f6738950e0e626b2ffc096bea3ef9d7ccaf713cafce8ae,
            0x44f82d2fe372488a2c728d5dbc7af6edc75707ba7073d48576ac2fb5a62f7c32,
            0x0a03d84e34145339edb94dc9abd591c3d504746b69d3d3237cdaf776c89316e2,
        ]
            .span(),
        elements_count: 197,
    }
}

fn proof_2() -> Proof {
    Proof {
        element_index: 16,
        element_hash: 0x7701fb3ede3096fad1b6546eb3ee18a395263631f21990289807b0364a50d3f4,
        siblings: array![
            0xcbc699c48bfd4df668eb7358b610fbec7b55c265ecb7c1c7d9fffdd0796fc2bd,
            0x9378e053e0debece3135c9630b8a6ffee46cb8c8484bf88849e21e6b7e7a9dce,
            0xcd0fe8e79cbff6574bb498ddb4f57437d506e262c435b03b55f13009c9a59232,
            0x57003624be61b0b94251ee30b2ac99335378f8e18abb8ccb4a5acb3510d33df4,
            0x92f102ed54dbaa2f90feb80c59bcebe03a5d04c66c93e109b2817d3455ef26c5,
            0xe907f19ebdd15613a45343e55c55dbdece057caeee84971f9ef99178086819a8
        ]
            .span(),
        peaks: array![
            0xe9bc1501c1b36bdef0f6738950e0e626b2ffc096bea3ef9d7ccaf713cafce8ae,
            0x44f82d2fe372488a2c728d5dbc7af6edc75707ba7073d48576ac2fb5a62f7c32,
            0x0a03d84e34145339edb94dc9abd591c3d504746b69d3d3237cdaf776c89316e2,
        ]
            .span(),
        elements_count: 197,
    }
}
