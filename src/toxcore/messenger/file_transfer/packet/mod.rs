/*! The implementation of packets for file sending.
*/

mod file_send_request;
mod file_data;
mod file_control;

pub use self::file_control::*;
pub use self::file_data::*;
pub use self::file_send_request::*;

use nom::be_u32;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Maximum size in bytes of chunk of file data
pub const MAX_FILE_DATA_SIZE: usize = 1371;

/// Type of file to transfer
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    /// Normal data file.
    Data = 0,
    /// Avatar image file.
    Avatar,
}

/// Maximum file name size in bytes
const MAX_FILESEND_FILENAME_LENGTH: usize = 255;

impl FromBytes for FileType {
    named!(from_bytes<FileType>,
        switch!(be_u32,
            0 => value!(FileType::Data) |
            1 => value!(FileType::Avatar)
        )
    );
}

const FILE_UID_BYTES: usize = 32;

/// A type for random 32 bytes which is used as file unique id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileUID([u8; FILE_UID_BYTES]);

impl FileUID {
    /// Create new object
    pub fn new() -> FileUID {
        let mut array = [0; FILE_UID_BYTES];
        randombytes_into(&mut array);
        FileUID(array)
    }

    fn from_slice(bs: &[u8]) -> Option<FileUID> {
        if bs.len() != FILE_UID_BYTES {
            return None
        }
        let mut n = FileUID([0; FILE_UID_BYTES]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for FileUID {
    named!(from_bytes<FileUID>, map_opt!(take!(FILE_UID_BYTES), FileUID::from_slice));
}

/** File sending packet enum that encapsulates all types of file sending packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`FileControl`](./struct.FileControl.html) structure.
    FileControl(FileControl),
    /// [`FileData`](./struct.FileData.html) structure.
    FileData(FileData),
    /// [`FileSendRequest`](./struct.FileSendRequest.html) structure.
    FileSendRequest(FileSendRequest),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::FileControl(ref p) => p.to_bytes(buf),
            Packet::FileData(ref p) => p.to_bytes(buf),
            Packet::FileSendRequest(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(FileControl::from_bytes, Packet::FileControl) |
        map!(FileData::from_bytes, Packet::FileData) |
        map!(FileSendRequest::from_bytes, Packet::FileSendRequest)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        packet_file_control_encode_decode,
        Packet::FileControl(FileControl::new(TransferDirection::Send, 1, ControlType::Seek(100)))
    );

    encode_decode_test!(
        packet_file_data_encode_decode,
        Packet::FileData(FileData::new(1, vec![1,2,3,4]))
    );

    encode_decode_test!(
        packet_file_send_request_encode_decode,
        Packet::FileSendRequest(FileSendRequest::new(1, FileType::Avatar, 4, FileUID::new(), "data".to_string()))
    );
}
