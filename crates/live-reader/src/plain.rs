//! Values that `Svm::read` can decode from little-endian process memory.

/// A fixed-size value decoded from little-endian bytes. Implemented for the primitive integers,
/// `f32`, `f64` and arrays of them.
pub trait Plain: Sized + private::Sealed {
    const SIZE: usize;

    /// `bytes` is exactly `SIZE` long.
    fn from_le_bytes(bytes: &[u8]) -> Self;
}

mod private {
    pub trait Sealed {}
}

macro_rules! primitive {
    ($($type:ty),*) => {$(
        impl private::Sealed for $type {}

        impl Plain for $type {
            const SIZE: usize = size_of::<$type>();

            fn from_le_bytes(bytes: &[u8]) -> Self {
                <$type>::from_le_bytes(bytes.try_into().expect("exact Plain size"))
            }
        }
    )*};
}

primitive!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64);

impl<T: Plain, const N: usize> private::Sealed for [T; N] {}

impl<T: Plain, const N: usize> Plain for [T; N] {
    const SIZE: usize = T::SIZE * N;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        std::array::from_fn(|index| T::from_le_bytes(&bytes[index * T::SIZE..][..T::SIZE]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<T: Plain>(bytes: &[u8]) -> T {
        T::from_le_bytes(bytes)
    }

    #[test]
    fn primitives_and_arrays_decode_little_endian() {
        assert_eq!(decode::<u32>(&[0x78, 0x56, 0x34, 0x12]), 0x1234_5678);
        assert_eq!(decode::<i16>(&[0xfe, 0xff]), -2);
        assert_eq!(decode::<f32>(&1.5f32.to_le_bytes()), 1.5);
        assert_eq!(<[u16; 3]>::SIZE, 6);
        assert_eq!(decode::<[u16; 3]>(&[1, 0, 2, 0, 3, 0]), [1, 2, 3]);
        assert_eq!(decode::<[[u8; 2]; 2]>(&[1, 2, 3, 4]), [[1, 2], [3, 4]]);
    }
}
