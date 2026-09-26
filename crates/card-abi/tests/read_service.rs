use svmvisor_card_abi::read_service::{
    MAX_READ_BYTES, Request, RequestError, Response, ResponseError, Status, crc32,
};

#[test]
fn request_rejects_corruption_reserved_words_and_unbounded_sources() {
    let request = Request::new(7, 9, 0x1234_5000, 32).unwrap();
    let words = request.encode();
    assert_eq!(Request::decode(&words), Ok(request));
    for index in 0..16 {
        let mut damaged = words;
        damaged[index] ^= 1;
        assert!(Request::decode(&damaged).is_err());
    }
    let mut reserved = words;
    reserved[14] = 1;
    reserved[15] = crc32(&reserved);
    assert_eq!(Request::decode(&reserved), Err(RequestError::Operation));
    for (gpa, length) in [(0xfffff, 1), (0x10_0fff, 2), (u64::MAX, 2), (0x10_0000, 33)] {
        assert!(Request::new(7, 9, gpa, length).is_err());
    }
    assert!(Request::new(0, 9, 0x10_0000, 1).is_err());
    assert!(Request::new(7, 0, 0x10_0000, 1).is_err());
}

#[test]
fn replies_bind_sequence_address_and_zero_unused_bytes() {
    let request = Request::new(7, 9, 0x1234_5000, 3).unwrap();
    let response = Response::new(request, 23, Status::Success, &[1, 2, 3]).unwrap();
    assert_eq!(Response::decode(request, response.encode()), Ok(response));
    assert_eq!(response.slot(), 23);
    assert_eq!(&response.bytes()[..3], &[1, 2, 3]);
    assert_eq!(&response.bytes()[3..], &[0; MAX_READ_BYTES - 3]);
    let other = Request::new(8, 9, request.gpa(), 3).unwrap();
    assert_eq!(Response::decode(other, response.encode()), Err(ResponseError::Identity));
    let mut leak = response.encode();
    leak[14] = 1;
    leak[15] = crc32(&leak);
    assert_eq!(Response::decode(request, leak), Err(ResponseError::Shape));
    assert!(Response::new(request, 0, Status::PhysicalRead, &[1]).is_err());
    let refusal = Response::new(request, 0, Status::PhysicalRead, &[]).unwrap();
    assert_eq!(refusal.bytes(), [0; MAX_READ_BYTES]);
    assert_eq!(Response::decode(request, refusal.encode()), Ok(refusal));
}

#[test]
fn ieee_crc_matches_independent_zlib_vector() {
    // Python zlib.crc32(bytes(60)), independent of our dword encoder.
    assert_eq!(crc32(&[0; 16]), 0x0412_8908);
}

#[test]
fn ft601_physical_frames_match_shared_wire_vectors() {
    let words: Vec<u32> = include_str!("../../../firmware/card/tests/ft601_wire_vectors.mem")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|line| u32::from_str_radix(line, 16).unwrap())
        .collect();
    assert_eq!(words.len(), 6 * 16);
    let frame =
        |index: usize| -> [u32; 16] { words[index * 16..(index + 1) * 16].try_into().unwrap() };
    let request = Request::new(0x1020_3040, 0xa1b2_c3d4, 0x1234_5000, 32).unwrap();
    assert_eq!(request.encode(), frame(0));
    let bytes: Vec<u8> = (0..32).collect();
    let response = Response::new(request, 3, Status::Success, &bytes).unwrap();
    assert_eq!(response.encode(), frame(1));
    assert_eq!(Response::decode(request, frame(1)), Ok(response));
    // USB identity is an FPGA operation, never a physical-read runtime command.
    assert_eq!(Request::decode(&frame(2)), Err(RequestError::Operation));
    for index in 0..6 {
        assert_eq!(crc32(&frame(index)), frame(index)[15]);
    }
}
