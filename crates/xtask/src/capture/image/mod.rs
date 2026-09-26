//! Bounded physical reads from explicitly selected offline capture formats.
//!
//! In raw mode file offset zero corresponds to the supplied physical base. Headers, compressed
//! pages and omitted physical runs must not be passed as raw memory. No format
//! detection or physical-base inference is performed. The file must remain unchanged while open;
//! the original length bounds reads, but this reader cannot establish snapshot consistency.
//! Filesystem sparse holes read as filesystem-provided zeros, not as unavailable physical memory.

use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

use crate::capture::image::bitmap::BitmapIndex;

#[cfg(test)]
pub(super) use self::bitmap::bitmap_dump_fixture;
pub(super) use self::dump::DumpMetadata;
#[cfg(test)]
pub(super) use self::dump::full_dump_fixture;

mod bitmap;
mod dump;

/// A read-only file handle with validated physical-to-file mappings.
pub(super) struct CaptureImage {
    file: File,
    runs: Vec<PhysicalRun>,
    bitmap: Option<BitmapIndex>,
    dump_metadata: Option<DumpMetadata>,
}

impl CaptureImage {
    pub(super) fn open_raw(path: &Path, physical_base: u64) -> Result<Self, ImageError> {
        let file = File::open(path).map_err(ImageError::Open)?;
        let metadata = file.metadata().map_err(ImageError::Metadata)?;
        if !metadata.is_file() {
            return Err(ImageError::NotRegularFile);
        }
        let length = metadata.len();
        if length == 0 {
            return Err(ImageError::EmptyImage);
        }
        physical_base.checked_add(length - 1).ok_or(ImageError::AddressOverflow)?;
        Ok(Self {
            file,
            runs: vec![PhysicalRun { start: physical_base, length, file_offset: 0 }],
            bitmap: None,
            dump_metadata: None,
        })
    }

    pub(super) fn max_physical_address(&self) -> u64 {
        if let Some(bitmap) = &self.bitmap {
            return bitmap.max_physical_address();
        }
        self.runs.iter().map(|run| run.start + (run.length - 1)).max().unwrap_or(0)
    }

    pub(super) fn dump_metadata(&self) -> Option<DumpMetadata> {
        self.dump_metadata
    }

    /// Fill the entire slice or return an error. Empty reads perform no I/O at any address.
    ///
    /// Range failures leave the slice unchanged. I/O failures can modify a prefix, so callers
    /// must discard the slice on error. The minimal reader supplies scratch for this purpose.
    pub(super) fn read(&mut self, pa: u64, bytes: &mut [u8]) -> Result<(), ImageError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let length = u64::try_from(bytes.len()).map_err(|_| ImageError::AddressOverflow)?;
        pa.checked_add(length - 1).ok_or(ImageError::AddressOverflow)?;
        // Validate the complete span before touching output, including gaps between dump runs.
        let mut address = pa;
        let mut remaining = length;
        while remaining != 0 {
            let run = self.run(address).ok_or(ImageError::OutsideImage)?;
            let count = remaining.min(run.length - (address - run.start));
            remaining -= count;
            if remaining != 0 {
                address = address.checked_add(count).ok_or(ImageError::AddressOverflow)?;
            }
        }

        let mut address = pa;
        let mut output = bytes;
        while !output.is_empty() {
            let run = self.run(address).ok_or(ImageError::OutsideImage)?;
            let within = address - run.start;
            let count = (run.length - within).min(output.len() as u64) as usize;
            let offset = run.file_offset + within;
            self.file.seek(SeekFrom::Start(offset)).map_err(ImageError::Seek)?;
            self.file.read_exact(&mut output[..count]).map_err(ImageError::Read)?;
            output = &mut output[count..];
            if !output.is_empty() {
                address += count as u64;
            }
        }
        Ok(())
    }

    fn run(&self, address: u64) -> Option<PhysicalRun> {
        if let Some(bitmap) = &self.bitmap {
            return bitmap.run(address);
        }
        self.runs
            .iter()
            .find(|run| address.checked_sub(run.start).is_some_and(|offset| offset < run.length))
            .copied()
    }
}

#[derive(Clone, Copy)]
struct PhysicalRun {
    start: u64,
    length: u64,
    file_offset: u64,
}

#[derive(Debug)]
pub(super) enum ImageError {
    Open(io::Error),
    Metadata(io::Error),
    NotRegularFile,
    EmptyImage,
    AddressOverflow,
    OutsideImage,
    Seek(io::Error),
    Read(io::Error),
    InvalidDump(&'static str),
}

impl fmt::Display for ImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(error) => write!(formatter, "cannot open capture: {error}"),
            Self::Metadata(error) => write!(formatter, "cannot inspect capture: {error}"),
            Self::NotRegularFile => formatter.write_str("capture must be a regular file"),
            Self::EmptyImage => formatter.write_str("raw capture is empty"),
            Self::AddressOverflow => formatter.write_str("capture physical range overflows u64"),
            Self::OutsideImage => formatter.write_str("physical range is absent from the capture"),
            Self::Seek(error) => write!(formatter, "cannot seek capture: {error}"),
            Self::Read(error) => write!(formatter, "cannot read complete capture range: {error}"),
            Self::InvalidDump(reason) => {
                write!(formatter, "unsupported or invalid dump: {reason}")
            }
        }
    }
}

impl Error for ImageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open(error) | Self::Metadata(error) | Self::Seek(error) | Self::Read(error) => {
                Some(error)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
