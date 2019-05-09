/*! The temporary friends and FileSending module for waiting completion of friends module.
*/

use std::ops::{Add, Sub};
use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use futures::{future, Future};
use futures::future::Either;
use futures::sync::mpsc::*;
use bitflags::*;

use crate::toxcore::messenger::file_transfer::packet::{Packet as FileSendingPacket, *};
use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::net_crypto::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::dht::packet::{MAX_CRYPTO_DATA_SIZE};
use crate::toxcore::messenger::file_transfer::errors::*;
use crate::toxcore::friend_connection::FriendConnections;

/// Because `file_id` is `u8` this const can not be larger than 256.
pub const MAX_CONCURRENT_FILE_PIPES: u32 = 256;

/// File transferring status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferStatus {
    /// Not accepted
    NotAccepted,
    /// Transferring
    Transferring,
    /// Finished
    Finished,
}

bitflags! {
    /// File transferring pause status
    pub struct PauseStatus: u8 {
        /// Not paused
        const FT_NONE = 0;
        /// Paused by us
        const US = 1;
        /// Paused by other
        const OTHER = 2;
        /// Paused by both
        const BOTH = 3;
    }
}

/** Struct holds info for each file sending job.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTransfers {
    /// Size in bytes of a file to transfer.
    pub size: u64,
    /// Size in bytes of a file already transferred.
    pub transferred: u64,
    /// Status of transferring.
    pub status: TransferStatus,
    /// Status of pausing.
    pub pause: PauseStatus,
    /// Number of last packet sent.
    pub last_packet_number: u32,
    /// Data requested by the request chunk callback.
    pub requested: u64,
    /// Unique file id for this transfer.
    pub unique_id: FileUID,
}

impl FileTransfers {
    /// Make new FileTransfers object
    pub fn new() -> Self {
        FileTransfers {
            size: 0,
            transferred: 0,
            status: TransferStatus::NotAccepted,
            pause: PauseStatus::FT_NONE,
            last_packet_number: 0,
            requested: 0,
            unique_id: FileUID::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct Friend {
    /// Number of files sending.
    num_sending_files: u8,
    /// File transfer objects for sending.
    files_sending: Vec<Option<FileTransfers>>,
    /// File transfer objects for receiving.
    files_receiving: Vec<Option<FileTransfers>>,
}

impl Friend {
    pub fn new() -> Self {
        Friend {
            num_sending_files: 0,
            files_receiving: Vec::new(),
            files_sending: Vec::new(),
        }
    }
}

/// FileSending object
#[derive(Clone)]
pub struct FileSending {
    /// Friends who are transferring files with us.
    friends: Arc<RwLock<HashMap<PublicKey, Friend>>>,
    friend_connections: FriendConnections,
    /// NetCrypto object
    net_crypto: NetCrypto,
    /// Sink for file control packets
    recv_file_control_tx: UnboundedSender<(PublicKey, FileSendingPacket)>,
    /// Sink for file data packets, `u64` is for file position which is a offset from the beginning of file.
    recv_file_data_tx: Sender<(PublicKey, FileSendingPacket, u64)>,
}

impl FileSending {
    /// Create new FileSending object
    pub fn new(
        friend_connections: FriendConnections,
        net_crypto: NetCrypto,
        recv_file_control_tx: UnboundedSender<(PublicKey, FileSendingPacket)>,
        recv_file_data_tx: Sender<(PublicKey, FileSendingPacket, u64)>,
    ) -> Self {
        FileSending {
            friends: Arc::new(RwLock::new(HashMap::new())),
            friend_connections,
            net_crypto,
            recv_file_control_tx,
            recv_file_data_tx,
        }
    }

    /// Send file control request.
    /// File control packet does some control action like Accept, Kill, Seek, Pause.
    fn send_file_control_packet(&self, pk: PublicKey, dir: TransferDirection, file_id: u8, control: ControlType)
                                -> impl Future<Item=(), Error=SendPacketError> + Send {
        let packet = FileControl::new(dir, file_id, control);
        let mut buf = [0; MAX_CRYPTO_DATA_SIZE];
        match packet.to_bytes((&mut buf, 0)) {
            Ok((data, size)) => {
                trace!("send file control packet {:?}", data[..size].to_vec().clone());
                Either::A(self.net_crypto.send_lossless(pk, data[..size].to_vec())
                    .map_err(|e| SendPacketError::from(e)))
            },
            Err(e) => {
                trace!("send control packet error {:?}", e);
                Either::B(future::err(SendPacketError::serialize(e)))
            },
        }
    }

    fn get_friend(&self, friend_pk: PublicKey) -> impl Future<Item=Friend, Error=SendPacketError> + Send {
        let mut friends = self.friends.write();
        friends.get_mut(&friend_pk)
            .map_or_else(
                || future::err(SendPacketErrorKind::NoFriend.into()),
                |friend| future::ok(friend.clone()))
    }

    /// Issue seek file control request
    /// This packet is for adjust the offset which is being transferred.
    /// Adjusting offset is needed for loss of file data packet while transferring.
    pub fn send_file_seek(&self, friend_pk: PublicKey, file_id: u8, position: u64) -> impl Future<Item=(), Error=SendPacketError> + Send + '_ {
        self.get_friend(friend_pk)
            .and_then(move |friend|
                self.clone().friend_connections.get_connection_status(friend_pk)
                    .map(|status| (status, friend))
                    .map_err(|_| SendPacketErrorKind::NotOnline.into())
            )
            .and_then(move |(status, friend)|
                if !status {
                    Err(SendPacketErrorKind::NotOnline.into())
                } else {
                    Ok(friend)
                }
            )
            .and_then(move |friend| {
                let files_receiving = friend.files_receiving.clone();
                files_receiving.get(file_id as usize)
                    .map_or_else(
                        || Err(SendPacketErrorKind::NoFileTransfer.into()),
                        |ft| Ok((friend, ft.clone(), file_id))
                    )
            })
            .and_then(|(friend, ft, file_id)|
                ft.map_or_else(|| Err(SendPacketErrorKind::NoFileTransfer.into()),
                                       |ft| Ok((friend, ft, file_id))
                )
            )
            .and_then(|(friend, ft, file_id)|
                if ft.status != TransferStatus::NotAccepted {
                    Err(SendPacketErrorKind::NotAccepted.into())
                } else { Ok((friend, ft, file_id)) }
            )
            .and_then(move |(friend, ft, file_id)| {
                if position >= ft.size {
                    Err(SendPacketErrorKind::LargerPosition.into())
                } else { Ok((friend, ft, file_id, position)) }
            })
            .and_then(move |(friend, ft, file_id, position)|
                self.clone()
                    .send_file_control_packet(friend_pk, TransferDirection::Receive, file_id, ControlType::Seek(position))
                    .map(move |_| (friend, ft, file_id))
            )
            .and_then(move |(mut friend, ft, file_id)| {
                let mut ft_c = ft.clone();
                ft_c.transferred = position;
                friend.files_receiving[file_id as usize] = Some(ft_c);
                Ok(())
            })
    }

    /// Issue file control request.
    pub fn send_file_control(&self, friend_pk: PublicKey, file_id: u8, dir: TransferDirection, control: ControlType)
                             -> impl Future<Item=(), Error=SendPacketError> + Send + '_ {
        self.get_friend(friend_pk)
            .and_then(move |friend|
                self.clone().friend_connections.get_connection_status(friend_pk)
                    .map(|status| (status, friend))
                    .map_err(|_| SendPacketErrorKind::NotOnline.into())
            )
            .and_then(move |(status, friend)|
                if !status {
                    Err(SendPacketErrorKind::NotOnline.into())
                } else {
                    Ok(friend)
                }
            )
            .and_then(move |friend| {
                if dir == TransferDirection::Send {
                    let files_sending = friend.files_sending.clone();
                    files_sending.get(file_id as usize)
                        .map_or_else(
                            || Err(SendPacketErrorKind::NoFileTransfer.into()),
                            |ft| Ok((friend, ft.clone(), file_id, dir))
                        )
                } else {
                    let files_receiving = friend.files_receiving.clone();
                    files_receiving.get(file_id as usize)
                        .map_or_else(
                            || Err(SendPacketErrorKind::NoFileTransfer.into()),
                            |ft| Ok((friend, ft.clone(), file_id, dir))
                        )
                }
            })
            .and_then(|(friend, ft, file_id, dir)|
                ft.map_or_else(
                        || Err(SendPacketErrorKind::NoFileTransfer.into()),
                        |ft| Ok((friend, ft.clone(), file_id, dir))
                    )
            )
            .and_then(|(friend, ft, file_id, dir)|
                if ft.status != TransferStatus::NotAccepted {
                    Err(SendPacketErrorKind::NotAccepted.into())
                } else {
                    Ok((friend, ft, file_id, dir))
                }
            )
            .and_then(move |(friend, ft, file_id, dir)|
                if control == ControlType::Pause && (ft.pause & PauseStatus::US == PauseStatus::US || ft.status != TransferStatus::Transferring) {
                    Err(SendPacketErrorKind::InvalidRequest.into())
                } else {
                    Ok((friend, ft, file_id, control, dir))
                }
            )
            .and_then(|(friend, ft, file_id, control, dir)| {
                if control == ControlType::Accept {
                    if ft.status == TransferStatus::Transferring {
                        if !(ft.pause & PauseStatus::US == PauseStatus::US) {
                            if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER {
                                return Err(SendPacketErrorKind::InvalidRequest2.into())
                            }
                            return Err(SendPacketErrorKind::InvalidRequest3.into())
                        }
                    } else {
                        if ft.status != TransferStatus::NotAccepted {
                            return Err(SendPacketErrorKind::InvalidRequest4.into())
                        }
                        if dir == TransferDirection::Send {
                            return Err(SendPacketErrorKind::InvalidRequest5.into())
                        }
                    }
                };
                Ok((friend, ft, file_id, control, dir))
            })
            .and_then(move |(friend, ft, file_id, control, dir)|
                self.clone().send_file_control_packet(friend_pk, dir, file_id, control)
                    .map(move |_| (friend, ft, file_id, control, dir))
            )
            .and_then(|(mut friend, ft, file_id, control, dir)| {
                let mut changed_ft = None;
                let mut ft_c = ft.clone();
                if control == ControlType::Kill {
                    if dir == TransferDirection::Send {
                        friend.num_sending_files = friend.num_sending_files.sub(1);
                    }
                } else if control == ControlType::Pause {
                    ft_c.pause = ft_c.pause | PauseStatus::US;
                    changed_ft = Some(ft_c);
                } else if control == ControlType::Accept {
                    ft_c.status = TransferStatus::Transferring;
                    changed_ft = Some(ft_c.clone());

                    if ft_c.pause & PauseStatus::US == PauseStatus::US {
                        ft_c.pause = ft_c.pause ^ PauseStatus::US;
                        changed_ft = Some(ft_c.clone());
                    }
                }
                if dir == TransferDirection::Send {
                    friend.files_sending[file_id as usize] = changed_ft;
                } else {
                    friend.files_receiving[file_id as usize] = changed_ft;
                }
                Ok(())
            })
    }

    fn recv_from(&self, friend_pk: PublicKey, packet: FileSendingPacket) -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let tx = self.recv_file_control_tx.clone();
        send_to(&tx, (friend_pk, packet))
            .map_err(|e| RecvPacketError::from(e))
    }

    fn recv_from_data(&self, friend_pk: PublicKey, packet: FileSendingPacket, position: u64) -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let tx = self.recv_file_data_tx.clone();
        send_to(&tx, (friend_pk, packet, position))
            .map_err(|e| RecvPacketError::from(e))
    }

    fn send_req_kill(&self, friend_pk: PublicKey, file_id: u8, transfer_direction: TransferDirection, control_type: ControlType)
                     -> impl Future<Item=(), Error=RecvPacketError> + Send {
        self.send_file_control_packet(friend_pk, transfer_direction, file_id, control_type)
            .map_err(|e| RecvPacketError::from(e))
    }

    /// Handle file control request packet
    pub fn handle_file_control(&self, friend_pk: PublicKey, packet: FileControl)
                           -> impl Future<Item=(), Error=RecvPacketError> + Send + '_ {
        self.get_friend(friend_pk)
            .map_err(|_| RecvPacketErrorKind::NoFriend.into())
            .and_then(move |friend| {
                if packet.transfer_direction == TransferDirection::Send {
                    let mut files_sending = friend.files_sending.clone();
                    files_sending.get_mut(packet.file_id as usize)
                        .map_or_else(
                            || Err(RecvPacketErrorKind::NoFileTransfer.into()),
                            |ft| Ok((friend, ft.clone(), packet))
                        )
                } else {
                    let mut files_receiving = friend.files_receiving.clone();
                    files_receiving.get_mut(packet.file_id as usize)
                        .map_or_else(
                            || Err(RecvPacketErrorKind::NoFileTransfer.into()),
                            |ft| Ok((friend, ft.clone(), packet))
                        )
                }
            })
            .and_then(move |(friend, ft, packet)| {
                let packet_c = packet.clone();
                let friend_c = friend.clone();
                ft.map_or_else(
                    move || {
                        warn!("file control (friend {:?}, file {}): file transfer does not exist; telling the other to kill it", friend_pk, packet_c.file_id);
                        return Either::A(self.send_req_kill(friend_pk, packet_c.file_id, packet_c.transfer_direction.toggle(), ControlType::Kill)
                            .map(|_| (friend_c, FileTransfers::new(), packet_c)))
                    },
                    |ft| Either::B(future::ok((friend, ft.clone(), packet)))
                )
            })
            .and_then(move |(mut friend, mut ft, packet)| {
                let up_packet = FileSendingPacket::FileControl(packet.clone());

                if packet.control_type == ControlType::Accept {
                    if packet.transfer_direction == TransferDirection::Receive && ft.status == TransferStatus::NotAccepted {
                        ft.status = TransferStatus::Transferring;
                    } else {
                        if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER {
                            ft.pause = ft.pause ^ PauseStatus::OTHER;
                        } else {
                            warn!("file control (friend {:?}, file {}): friend told us to resume file transfer that wasn't paused", friend_pk, packet.file_id);
                            return Err(RecvPacketError::invalid_request(friend_pk, packet.file_id))
                        }
                    }
                } else if packet.control_type == ControlType::Pause {
                    if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER || ft.status != TransferStatus::Transferring {
                        warn!("file control (friend {:?}, file {}): friend told us to pause file transfer that is already paused", friend_pk, packet.file_id);
                        return Err(RecvPacketError::invalid_request(friend_pk, packet.file_id))
                    }

                    ft.pause = ft.pause | PauseStatus::OTHER;
                } else if packet.control_type == ControlType::Kill {
                    if packet.transfer_direction == TransferDirection::Receive {
                        friend.num_sending_files = friend.num_sending_files.sub(1);
                        friend.files_receiving[packet.file_id as usize] = None;
                    } else {
                        friend.files_sending[packet.file_id as usize] = None;
                    }
                } else if let ControlType::Seek(position) = packet.control_type {
                    if ft.status != TransferStatus::NotAccepted || packet.transfer_direction == TransferDirection::Send {
                        warn!("file control (friend {:?}, file {}): seek was either sent by a sender or by the receiver after accepting", friend_pk, packet.file_id);
                        return Err(RecvPacketError::invalid_request(friend_pk, packet.file_id))
                    }
                    if position >= ft.size {
                        warn!("file control (friend {:?}, file {}): seek position {} exceeds file size {}", friend_pk, packet.file_id, position, ft.size);
                        return Err(RecvPacketError::exceed_size(friend_pk, packet.file_id, ft.size))
                    }
                    ft.requested = position;
                    ft.transferred = position;
                } else { // unknown file control
                    return Err(RecvPacketErrorKind::UnknownControlType.into())
                }
                Ok(up_packet)
            })
            .and_then(move |up_packet|

                self.clone().recv_from(friend_pk, up_packet)
            )
    }

    /// Handle file send request packet
    pub fn handle_file_send_request(&self, friend_pk: PublicKey, packet: FileSendRequest)
                                -> impl Future<Item=(), Error=RecvPacketError> + Send + '_ {
        self.get_friend(friend_pk)
            .map_err(|_| RecvPacketErrorKind::NoFriend.into())
            .and_then(move |friend| {
                let mut files_receiving = friend.files_receiving.clone();
                files_receiving.get_mut(packet.file_id as usize)
                    .map_or_else(
                        || Ok((friend, packet)),
                        |_| Err(RecvPacketErrorKind::NoFileTransfer.into())
                    )
            })
            .and_then(move |(mut friend, packet)| {
                let mut ft = FileTransfers::new();

                ft.status = TransferStatus::NotAccepted;
                ft.size = packet.file_size;
                ft.transferred = 0;
                ft.pause = PauseStatus::FT_NONE;

                friend.files_receiving[packet.file_id as usize] = Some(ft);

                self.clone().recv_from(friend_pk, FileSendingPacket::FileSendRequest(packet))
            })
    }

    /// Handle file data packet
    pub fn handle_file_data(&self, friend_pk: PublicKey, packet: FileData)
                        -> impl Future<Item=(), Error=RecvPacketError> + Send + '_ {
        self.get_friend(friend_pk)
            .map_err(|_| RecvPacketErrorKind::NoFriend.into())
            .and_then(move |friend| {
                let mut files_receiving = friend.files_receiving.clone();
                files_receiving.get_mut(packet.file_id as usize)
                    .map_or_else(
                        || Err(RecvPacketErrorKind::NoFileTransfer.into()),
                        |ft| Ok((friend, ft.clone(), packet))
                    )
            })
            .and_then(|(friend, ft, packet)|
                ft.map_or_else(
                    || Err(RecvPacketErrorKind::NoFileTransfer.into()),
                    |ft| Ok((friend, ft.clone(), packet))
                )
            )
            .and_then(move |(friend, mut ft, mut packet)| {
                if ft.status != TransferStatus::Transferring {
                    return Err(RecvPacketErrorKind::NotTransferring.into())
                }

                let mut data_len = packet.data.len() as u64;
                let position = ft.transferred;

                // Prevent more data than the filesize from being passed to clients.
                if ft.transferred + data_len > ft.size {
                    data_len = ft.size - ft.transferred;
                    packet.data.drain(..data_len as usize);
                }

                ft.transferred = ft.transferred.add(data_len);

                let up_packet = FileSendingPacket::FileData(packet.clone());
                Ok((friend, ft, packet, data_len, position, up_packet))
            })
            .and_then(move |(friend, ft, packet, data_len, position, up_packet)|
                self.clone().recv_from_data(friend_pk, up_packet, position)
                    .map(move |_| (friend, ft, packet, data_len, position))
            )
            .and_then(move |(mut friend, ft, packet, data_len, position)| {
                if data_len == 0 {
                    friend.files_receiving[packet.file_id as usize] = None;
                }

                if data_len > 0 && (ft.transferred >= ft.size || data_len != MAX_FILE_DATA_SIZE as u64) {
                    let packet = FileSendingPacket::FileData(FileData::new(packet.file_id, Vec::new()));
                    Either::A(self.recv_from_data(friend_pk, packet, position))
                } else {
                    Either::B(future::ok(()))
                }
            })
    }
}
