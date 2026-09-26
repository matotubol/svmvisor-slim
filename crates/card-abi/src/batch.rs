//! Transport-independent batch wire contract. CRC protects framing, not authentication.

pub const MAGIC: u32 = 0x3242_5453;
pub const VERSION: u16 = 2;
pub const REQUEST_BYTES: usize = 256;
pub const HEADER_BYTES: usize = 64;
pub const MAX_RANGES: usize = 8;
pub const MAX_DATA_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = HEADER_BYTES + MAX_DATA_BYTES + 4;

// IEEE CRC-32 in reflected byte order. Generated at compile time; the resident
// uses one scalar table lookup per byte with no CPU feature or SIMD dependency.
const CRC32_TABLE: [u32; 256] = crc32_table();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchRequest {
    pub operation: Operation,
    pub session: u64,
    pub boot: u64,
    pub sequence: u64,
    pub token: u64,
    pub count: usize,
    pub ranges: [BatchRange; MAX_RANGES],
    pub binding: BindingEvidence,
}

impl BatchRequest {
    pub fn decode(bytes: &[u8; REQUEST_BYTES]) -> Result<Self, FrameError> {
        if word(bytes, 0) != MAGIC || word(bytes, 4) as u16 != VERSION {
            return Err(FrameError::Header);
        }
        if crc32(&bytes[..252]) != word(bytes, 252) {
            return Err(FrameError::Checksum);
        }
        let operation = match word(bytes, 4) >> 16 {
            0 => Operation::Hello,
            1 => Operation::Physical,
            2 => Operation::Bind,
            3 => Operation::Sample,
            _ => return Err(FrameError::Operation),
        };
        let mut request = Self {
            operation,
            session: wide(bytes, 8),
            boot: wide(bytes, 16),
            sequence: wide(bytes, 24),
            token: wide(bytes, 32),
            count: word(bytes, 40) as usize,
            ranges: [BatchRange::EMPTY; MAX_RANGES],
            binding: BindingEvidence::EMPTY,
        };
        if request.session == 0 || request.sequence == 0 || word(bytes, 44) != 0 {
            return Err(FrameError::Shape);
        }
        let end = match operation {
            Operation::Hello => {
                if request.boot != 0 || request.token != 0 || request.count != 0 {
                    return Err(FrameError::Shape);
                }
                48
            }
            Operation::Physical | Operation::Sample => {
                if request.count == 0
                    || request.count > MAX_RANGES
                    || (operation == Operation::Physical && request.token != 0)
                    || (operation == Operation::Sample && request.token == 0)
                {
                    return Err(FrameError::Shape);
                }
                let mut total = 0usize;
                for index in 0..request.count {
                    let offset = 48 + index * 16;
                    let range = BatchRange {
                        address: wide(bytes, offset),
                        length: word(bytes, offset + 8),
                    };
                    if range.length == 0
                        || word(bytes, offset + 12) != 0
                        || range.address.checked_add(u64::from(range.length) - 1).is_none()
                    {
                        return Err(FrameError::Shape);
                    }
                    total = total.checked_add(range.length as usize).ok_or(FrameError::Shape)?;
                    request.ranges[index] = range;
                }
                if total > MAX_DATA_BYTES {
                    return Err(FrameError::Shape);
                }
                48 + request.count * 16
            }
            Operation::Bind => {
                if request.count != 0 || request.token != 0 || word(bytes, 108) > 0x0fff {
                    return Err(FrameError::Shape);
                }
                request.binding = BindingEvidence {
                    kernel_root: wide(bytes, 48),
                    target_root: wide(bytes, 56),
                    pid: wide(bytes, 64),
                    object: wide(bytes, 72),
                    creation: wide(bytes, 80),
                    object_bytes: word(bytes, 88),
                    links_offset: word(bytes, 92),
                    pid_offset: word(bytes, 96),
                    root_offset: word(bytes, 100),
                    creation_offset: word(bytes, 104),
                    root_mask: word(bytes, 108) as u16,
                };
                112
            }
        };
        if bytes[end..252].iter().any(|byte| *byte != 0) {
            return Err(FrameError::Shape);
        }
        Ok(request)
    }

    pub fn encode(self) -> [u8; REQUEST_BYTES] {
        let mut bytes = [0; REQUEST_BYTES];
        put_word(&mut bytes, 0, MAGIC);
        put_word(&mut bytes, 4, u32::from(VERSION) | ((self.operation as u32) << 16));
        put_wide(&mut bytes, 8, self.session);
        put_wide(&mut bytes, 16, self.boot);
        put_wide(&mut bytes, 24, self.sequence);
        put_wide(&mut bytes, 32, self.token);
        put_word(&mut bytes, 40, self.count as u32);
        if self.operation == Operation::Bind {
            let binding = self.binding;
            for (index, value) in [
                binding.kernel_root,
                binding.target_root,
                binding.pid,
                binding.object,
                binding.creation,
            ]
            .into_iter()
            .enumerate()
            {
                put_wide(&mut bytes, 48 + index * 8, value);
            }
            for (index, value) in [
                binding.object_bytes,
                binding.links_offset,
                binding.pid_offset,
                binding.root_offset,
                binding.creation_offset,
                u32::from(binding.root_mask),
            ]
            .into_iter()
            .enumerate()
            {
                put_word(&mut bytes, 88 + index * 4, value);
            }
        } else {
            for (index, range) in self.ranges.iter().take(self.count.min(MAX_RANGES)).enumerate() {
                put_wide(&mut bytes, 48 + index * 16, range.address);
                put_word(&mut bytes, 56 + index * 16, range.length);
            }
        }
        let crc = crc32(&bytes[..252]);
        put_word(&mut bytes, 252, crc);
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchRange {
    pub address: u64,
    pub length: u32,
}

impl BatchRange {
    pub const EMPTY: Self = Self { address: 0, length: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingEvidence {
    pub kernel_root: u64,
    pub target_root: u64,
    pub pid: u64,
    pub object: u64,
    pub creation: u64,
    pub object_bytes: u32,
    pub links_offset: u32,
    pub pid_offset: u32,
    pub root_offset: u32,
    pub creation_offset: u32,
    pub root_mask: u16,
}

impl BindingEvidence {
    pub const EMPTY: Self = Self {
        kernel_root: 0,
        target_root: 0,
        pid: 0,
        object: 0,
        creation: 0,
        object_bytes: 0,
        links_offset: 0,
        pid_offset: 0,
        root_offset: 0,
        creation_offset: u32::MAX,
        root_mask: 0,
    };
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Hello = 0,
    Physical = 1,
    Bind = 2,
    Sample = 3,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Success = 0,
    Identity = 1,
    Sequence = 2,
    Binding = 3,
    Read = 4,
    Shape = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    Header,
    Checksum,
    Operation,
    Shape,
}

/// Encode only actual data; callers publish the returned byte count atomically.
pub fn encode_response(
    request: BatchRequest,
    boot: u64,
    token: u64,
    status: Status,
    data: &[u8],
    output: &mut [u8; MAX_RESPONSE_BYTES],
) -> Result<usize, FrameError> {
    if data.len() > MAX_DATA_BYTES || (status != Status::Success && !data.is_empty()) {
        return Err(FrameError::Shape);
    }
    let length = HEADER_BYTES + ((data.len() + 3) & !3) + 4;
    output[..length].fill(0);
    put_word(output, 0, MAGIC);
    put_word(output, 4, u32::from(VERSION) | ((request.operation as u32) << 16));
    put_wide(output, 8, request.session);
    put_wide(output, 16, boot);
    put_wide(output, 24, request.sequence);
    put_wide(output, 32, token);
    put_word(output, 40, status as u32);
    put_word(output, 44, data.len() as u32);
    put_word(output, 48, request.count as u32);
    output[HEADER_BYTES..HEADER_BYTES + data.len()].copy_from_slice(data);
    let crc = crc32(&output[..length - 4]);
    put_word(output, length - 4, crc);
    Ok(length)
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc = (crc >> 8) ^ CRC32_TABLE[((crc as u8) ^ byte) as usize];
    }
    !crc
}

const fn crc32_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut index = 0;
    while index < table.len() {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn wide(bytes: &[u8], offset: usize) -> u64 {
    u64::from(word(bytes, offset)) | (u64::from(word(bytes, offset + 4)) << 32)
}

fn put_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_wide(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn physical() -> BatchRequest {
        let mut ranges = [BatchRange::EMPTY; MAX_RANGES];
        ranges[0] = BatchRange { address: 0x0010_0000, length: 4096 };
        BatchRequest {
            operation: Operation::Physical,
            session: 9,
            boot: 8,
            sequence: 7,
            token: 0,
            count: 1,
            ranges,
            binding: BindingEvidence::EMPTY,
        }
    }

    #[test]
    fn round_trip_and_crc_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let request = physical();
        assert_eq!(BatchRequest::decode(&request.encode()), Ok(request));
        let mut bytes = request.encode();
        bytes[100] ^= 1;
        assert_eq!(BatchRequest::decode(&bytes), Err(FrameError::Checksum));
    }

    #[test]
    fn crc_matches_independent_wire_length_and_unaligned_vectors() {
        // Python zlib.crc32 over bytes((i * 73 + 19) & 255 for i in range(4168)).
        // Covers every byte value, request/response sizes and unaligned slices.
        let data: [u8; 4168] = core::array::from_fn(|index| (index * 73 + 19) as u8);
        for (length, expected) in [
            (0, 0),
            (1, 0x56bc_ae53),
            (3, 0x5193_8104),
            (4, 0x928c_776a),
            (7, 0xc66e_a606),
            (8, 0xc81e_5556),
            (64, 0x96af_c5a6),
            (252, 0xc7f7_5f01),
            (256, 0x5da8_967f),
            (4160, 0xe419_c2ff),
        ] {
            assert_eq!(crc32(&data[..length]), expected, "length={length}");
        }
        for (offset, expected) in [
            0x7719_bc29,
            0xb21c_980b,
            0x77c0_ae6b,
            0x7a59_839d,
            0x0571_3f15,
            0x105c_4cff,
            0x88a4_18c0,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(crc32(&data[offset + 1..offset + 4161]), expected);
        }
    }

    #[test]
    fn rejects_oversize_overflow_reserved_and_unknown_operations() {
        let mut request = physical();
        request.ranges[0].length = 4097;
        assert_eq!(BatchRequest::decode(&request.encode()), Err(FrameError::Shape));
        request.ranges[0] = BatchRange { address: u64::MAX, length: 2 };
        assert_eq!(BatchRequest::decode(&request.encode()), Err(FrameError::Shape));
        let mut bytes = physical().encode();
        bytes[200] = 1;
        let crc = crc32(&bytes[..252]);
        put_word(&mut bytes, 252, crc);
        assert_eq!(BatchRequest::decode(&bytes), Err(FrameError::Shape));
        put_word(&mut bytes, 4, u32::from(VERSION) | (4 << 16));
        let crc = crc32(&bytes[..252]);
        put_word(&mut bytes, 252, crc);
        assert_eq!(BatchRequest::decode(&bytes), Err(FrameError::Operation));
    }

    #[test]
    fn responses_are_short_padded_and_failures_contain_no_data() {
        let mut output = [0xff; MAX_RESPONSE_BYTES];
        let length =
            encode_response(physical(), 8, 0, Status::Success, &[1, 2, 3], &mut output).unwrap();
        assert_eq!(length, 72);
        assert_eq!(&output[64..68], &[1, 2, 3, 0]);
        assert_eq!(word(&output, 68), crc32(&output[..68]));
        assert_eq!(
            encode_response(physical(), 8, 0, Status::Read, &[1], &mut output),
            Err(FrameError::Shape)
        );
        assert_eq!(encode_response(physical(), 8, 0, Status::Read, &[], &mut output), Ok(68));
    }
}
