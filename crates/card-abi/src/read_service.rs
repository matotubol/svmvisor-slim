//! Explicit USER4 diagnostic mailbox. Frames are sixteen little-endian dwords.
//! CRC detects transmission errors; it is not authentication or a memory-lifetime proof.

pub const FRAME_WORDS: usize = 16;
pub const MAX_READ_BYTES: usize = 32;
pub const REQUEST_BASE: u64 = 0x500;
pub const RESPONSE_BASE: u64 = 0x540;
pub const RESPONSE_COMMIT: u64 = 0x580;
pub const CAPABILITY_OFFSET: u64 = 0x584;
pub const CAPABILITY: u32 = 0x3152_5653;
pub const ACTIVE_SEQUENCE: u64 = 0x588;
pub const RESPONSE_SEQUENCE: u64 = 0x58c;
pub const REQUEST_MAGIC: u32 = 0x5152_5653;
pub const RESPONSE_MAGIC: u32 = 0x5052_5653;
pub const VERSION: u32 = 1;
const READ_PHYSICAL: u32 = 1;
const PAGE_BYTES: u64 = 4096;
const LOW_RAM_END: u64 = 0x0010_0000;

/// Shape-validated physical observation; runtime must independently admit the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    sequence: u32,
    boot_id: u32,
    gpa: u64,
    length: usize,
}

impl Request {
    pub fn new(sequence: u32, boot_id: u32, gpa: u64, length: usize) -> Result<Self, RequestError> {
        if sequence == 0 || boot_id == 0 {
            return Err(RequestError::Identity);
        }
        if length == 0 || length > MAX_READ_BYTES {
            return Err(RequestError::Length);
        }
        if gpa < LOW_RAM_END
            || gpa.checked_add(length as u64 - 1).is_none()
            || (gpa & (PAGE_BYTES - 1)) + length as u64 > PAGE_BYTES
        {
            return Err(RequestError::Range);
        }
        Ok(Self { sequence, boot_id, gpa, length })
    }

    pub fn decode(words: &[u32; FRAME_WORDS]) -> Result<Self, RequestError> {
        if words[0] != REQUEST_MAGIC || words[1] != VERSION {
            return Err(RequestError::Header);
        }
        if crc32(words) != words[15] {
            return Err(RequestError::Checksum);
        }
        if words[3] != READ_PHYSICAL || words[8..15].iter().any(|word| *word != 0) {
            return Err(RequestError::Operation);
        }
        Self::new(
            words[2],
            words[7],
            u64::from(words[5]) | (u64::from(words[6]) << 32),
            words[4] as usize,
        )
    }

    pub const fn sequence(self) -> u32 {
        self.sequence
    }
    pub const fn boot_id(self) -> u32 {
        self.boot_id
    }
    pub const fn gpa(self) -> u64 {
        self.gpa
    }
    pub const fn length(self) -> usize {
        self.length
    }

    pub fn encode(self) -> [u32; FRAME_WORDS] {
        let mut words = [0; FRAME_WORDS];
        words[0] = REQUEST_MAGIC;
        words[1] = VERSION;
        words[2] = self.sequence;
        words[3] = READ_PHYSICAL;
        words[4] = self.length as u32;
        words[5] = self.gpa as u32;
        words[6] = (self.gpa >> 32) as u32;
        words[7] = self.boot_id;
        words[15] = crc32(&words);
        words
    }
}

/// Reply owns its bytes and never names a guest destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    words: [u32; FRAME_WORDS],
}

impl Response {
    pub fn new(
        request: Request,
        slot: usize,
        status: Status,
        bytes: &[u8],
    ) -> Result<Self, ResponseError> {
        if slot >= 32
            || (status == Status::Success && bytes.len() != request.length())
            || (status != Status::Success && !bytes.is_empty())
        {
            return Err(ResponseError::Shape);
        }
        let mut words = [0; FRAME_WORDS];
        words[0] = RESPONSE_MAGIC;
        words[1] = VERSION;
        words[2] = request.sequence();
        words[3] = status.code();
        words[4] = bytes.len() as u32 | ((slot as u32) << 16);
        words[5] = request.gpa() as u32;
        words[6] = (request.gpa() >> 32) as u32;
        for (index, byte) in bytes.iter().enumerate() {
            words[7 + index / 4] |= u32::from(*byte) << ((index % 4) * 8);
        }
        words[15] = crc32(&words);
        Ok(Self { words })
    }

    /// Reject an immutable mailbox frame without admitting or dereferencing its address.
    pub fn refusal(
        sequence: u32,
        gpa: u64,
        slot: usize,
        status: Status,
    ) -> Result<Self, ResponseError> {
        if sequence == 0 || slot >= 32 || status == Status::Success {
            return Err(ResponseError::Shape);
        }
        let mut words = [0; FRAME_WORDS];
        words[0] = RESPONSE_MAGIC;
        words[1] = VERSION;
        words[2] = sequence;
        words[3] = status.code();
        words[4] = (slot as u32) << 16;
        words[5] = gpa as u32;
        words[6] = (gpa >> 32) as u32;
        words[15] = crc32(&words);
        Ok(Self { words })
    }

    pub fn decode(request: Request, words: [u32; FRAME_WORDS]) -> Result<Self, ResponseError> {
        if words[0] != RESPONSE_MAGIC || words[1] != VERSION || crc32(&words) != words[15] {
            return Err(ResponseError::Header);
        }
        if words[2] != request.sequence()
            || words[5] != request.gpa() as u32
            || words[6] != (request.gpa() >> 32) as u32
        {
            return Err(ResponseError::Identity);
        }
        let status = Status::from_code(words[3]).ok_or(ResponseError::Status)?;
        let length = (words[4] & 0xffff) as usize;
        if words[4] >> 16 >= 32
            || length > MAX_READ_BYTES
            || (status == Status::Success && length != request.length())
            || (status != Status::Success && length != 0)
        {
            return Err(ResponseError::Shape);
        }
        for index in length..MAX_READ_BYTES {
            if (words[7 + index / 4] >> ((index % 4) * 8)) & 255 != 0 {
                return Err(ResponseError::Shape);
            }
        }
        Ok(Self { words })
    }

    pub fn status(self) -> Status {
        // Construction and decode both validate this discriminant.
        Status::from_code(self.words[3]).unwrap_or(Status::Unsupported)
    }

    pub const fn length(self) -> usize {
        (self.words[4] & 0xffff) as usize
    }
    pub const fn slot(self) -> usize {
        (self.words[4] >> 16) as usize
    }
    pub const fn encode(self) -> [u32; FRAME_WORDS] {
        self.words
    }

    pub fn bytes(self) -> [u8; MAX_READ_BYTES] {
        let mut bytes = [0; MAX_READ_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (self.words[7 + index / 4] >> ((index % 4) * 8)) as u8;
        }
        bytes
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Success = 0,
    Shape = 1,
    NestedRoot = 2,
    NestedMapping = 3,
    PhysicalRead = 4,
    Busy = 5,
    Unsupported = 6,
}

impl Status {
    pub const fn code(self) -> u32 {
        self as u32
    }
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            1 => Some(Self::Shape),
            2 => Some(Self::NestedRoot),
            3 => Some(Self::NestedMapping),
            4 => Some(Self::PhysicalRead),
            5 => Some(Self::Busy),
            6 => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    Identity,
    Length,
    Range,
    Header,
    Checksum,
    Operation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseError {
    Shape,
    Header,
    Identity,
    Status,
}

/// IEEE CRC-32 over the first fifteen dwords, least-significant byte first.
pub fn crc32(words: &[u32; FRAME_WORDS]) -> u32 {
    let mut crc = u32::MAX;
    for word in &words[..15] {
        for byte in word.to_le_bytes() {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
    }
    !crc
}
