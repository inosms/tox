/*! The implementation of Friend connection
*/

pub mod packet;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use failure::Fail;
use futures::{Future, Stream, future};
use futures::future::Either;
use futures::sync::mpsc;
use parking_lot::RwLock;
use tokio::timer::Interval;
use tokio::util::FutureExt;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::dht_node::BAD_NODE_TIMEOUT;
use crate::toxcore::dht::packed_node::PackedNode;
use crate::toxcore::dht::server::{Server as DhtServer};
use crate::toxcore::net_crypto::NetCrypto;
use crate::toxcore::net_crypto::errors::KillConnectionErrorKind;
use crate::toxcore::onion::client::OnionClient;
use crate::toxcore::tcp::client::{Connections as TcpConnections, RECOMMENDED_FRIEND_TCP_CONNECTIONS};
use crate::toxcore::time::*;

const PACKET_ID_ALIVE: u8 = 16;

const PACKET_ID_SHARE_RELAYS: u8 = 17;

/// How often we should send ping packets to a friend.
const FRIEND_PING_INTERVAL: Duration = Duration::from_secs(8);

/// How often the main loop should be called.
const MAIN_LOOP_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum number of TCP relays `ShareRelays` packet can carry.
const MAX_SHARED_RELAYS: usize = RECOMMENDED_FRIEND_TCP_CONNECTIONS;

/// After this amount of time with no connection friend's DHT `PublicKey` and IP
/// address will be considered timed out.
const FRIEND_DHT_TIMEOUT: Duration = Duration::from_secs(BAD_NODE_TIMEOUT);

/** Packed used to share our relays with a friend.

Serialized form:

Length     | Content
---------- | ------
`1`        | `0x11`
`[0, 153]` | Nodes in packed format

*/
struct ShareRelays {
    /// Relays we are connected to.
    nodes: Vec<PackedNode>,
}

impl FromBytes for ShareRelays {
    named!(from_bytes<ShareRelays>, do_parse!(
        tag!(&[PACKET_ID_SHARE_RELAYS][..]) >>
        nodes: many0!(PackedNode::from_tcp_bytes) >>
        cond_reduce!(nodes.len() <= MAX_SHARED_RELAYS, eof!()) >>
        (ShareRelays {
            nodes
        })
    ));
}

impl ToBytes for ShareRelays {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(PACKET_ID_SHARE_RELAYS) >>
            gen_cond!(
                self.nodes.len() <= MAX_SHARED_RELAYS,
                gen_many_ref!(&self.nodes, |buf, node| PackedNode::to_tcp_bytes(node, buf))
            )
        )
    }
}

#[derive(Clone, Debug)]
struct Friend {
    /// Friend's long term `PublicKey`.
    real_pk: PublicKey,
    /// Friend's DHT `PublicKey` when it's known.
    dht_pk: Option<PublicKey>,
    /// Friend's IP address when it's known.
    saddr: Option<SocketAddr>,
    /// Time when we received friend's DHT `PublicKey`.
    dht_pk_time: Option<Instant>,
    /// Time when we received friend's IP address.
    saddr_time: Option<Instant>,
    /// Whether we connected to this friend.
    connected: bool,
    /// Time when we sent the last ping packet.
    ping_sent_time: Instant,
    /// Time when we received the last ping packet.
    ping_received_time: Instant,
}

impl Friend {
    pub fn new(real_pk: PublicKey) -> Self {
        Friend {
            real_pk,
            dht_pk: None,
            saddr: None,
            dht_pk_time: None,
            saddr_time: None,
            connected: false,
            ping_sent_time: clock_now(),
            ping_received_time: clock_now(),
        }
    }
}

#[derive(Clone)]
pub struct FriendConnections {
    /// Our long term `SecretKey`.
    real_sk: SecretKey,
    /// Our long term `PublicKey`.
    real_pk: PublicKey,
    /// List of friends we want to be connected to.
    friends: Arc<RwLock<HashMap<PublicKey, Friend>>>,
    /// DHT server.
    dht: DhtServer,
    tcp_connections: TcpConnections,
    onion_client: OnionClient,
    net_crypto: NetCrypto,
}

impl FriendConnections {
    /// Create new `FriendConnections`.
    pub fn new(
        real_sk: SecretKey,
        real_pk: PublicKey,
        dht: DhtServer,
        tcp_connections: TcpConnections,
        onion_client: OnionClient,
        net_crypto: NetCrypto,
    ) -> Self {
        FriendConnections {
            real_sk,
            real_pk,
            friends: Arc::new(RwLock::new(HashMap::new())),
            dht,
            tcp_connections,
            onion_client,
            net_crypto,
        }
    }

    /// Add a friend we want to be connected to.
    pub fn add_friend(&self, friend_pk: PublicKey) {
        let mut friends = self.friends.write();
        if let Entry::Vacant(entry) = friends.entry(friend_pk) {
            entry.insert(Friend::new(friend_pk));
            self.onion_client.add_friend(friend_pk);
            self.net_crypto.add_friend(friend_pk);
        }
    }

    /// Remove a friend and drop all connections with him.
    pub fn remove_friend(&self, friend_pk: PublicKey) -> impl Future<Item = (), Error = Error> + Send {
        let mut friends = self.friends.write();
        if let Some(friend) = friends.remove(&friend_pk) {
            if let Some(dht_pk) = friend.dht_pk {
                self.dht.remove_friend(dht_pk);
            }
            Either::A(self.net_crypto.kill_connection(friend_pk)
                .then(|res| match res {
                    Err(ref e) if *e.kind() == KillConnectionErrorKind::NoConnection => Ok(()),
                    res => res,
                })
                .map_err(|e| Error::new(ErrorKind::Other, e.compat())))
        } else {
            Either::B(future::ok(()))
        }
    }

    /// Handle the stream of found DHT `PublicKey`s.
    fn handle_dht_pk(&self, dht_pk_rx: mpsc::UnboundedReceiver<(PublicKey, PublicKey)>) -> impl Future<Item = (), Error = Error> + Send {
        let dht = self.dht.clone();
        let net_crypto = self.net_crypto.clone();
        let onion_client = self.onion_client.clone();
        let friends = self.friends.clone();
        dht_pk_rx
            .map_err(|()| -> Error { unreachable!("rx can't fail") })
            .for_each(move |(real_pk, dht_pk)| {
                if let Some(friend) = friends.write().get_mut(&real_pk) {
                    friend.dht_pk_time = Some(clock_now());

                    if friend.dht_pk != Some(dht_pk) {
                        info!("Found a friend's DHT key");

                        let kill_connection_future = if let Some(dht_pk) = friend.dht_pk {
                            dht.remove_friend(dht_pk);
                            Either::A(net_crypto.kill_connection(real_pk)
                                .then(|res| match res {
                                    Err(ref e) if *e.kind() == KillConnectionErrorKind::NoConnection => Ok(()),
                                    res => res,
                                })
                                .map_err(|e| Error::new(ErrorKind::Other, e.compat())))
                        } else {
                            Either::B(future::ok(()))
                        };

                        friend.dht_pk = Some(dht_pk);

                        dht.add_friend(dht_pk);
                        net_crypto.add_connection(real_pk, dht_pk);
                        onion_client.set_friend_dht_pk(real_pk, dht_pk);

                        kill_connection_future
                    } else {
                        Either::B(future::ok(()))
                    }
                } else {
                    Either::B(future::ok(()))
                }
            })
    }

    /// Handle the stream of found IP addresses.
    fn handle_friend_saddr(&self, friend_saddr_rx: mpsc::UnboundedReceiver<PackedNode>) -> impl Future<Item = (), Error = Error> + Send {
        let net_crypto = self.net_crypto.clone();
        let friends = self.friends.clone();
        friend_saddr_rx
            .map_err(|()| -> Error { unreachable!("rx can't fail") })
            .for_each(move |node| {
                if let Some(friend) = friends.write().values_mut().find(|friend| friend.dht_pk == Some(node.pk)) {
                    friend.saddr_time = Some(clock_now());

                    if friend.saddr != Some(node.saddr) {
                        info!("Found a friend's IP address");

                        friend.saddr = Some(node.saddr);

                        net_crypto.add_connection(friend.real_pk, node.pk);
                        net_crypto.set_friend_udp_addr(friend.real_pk, node.saddr);
                    }
                }

                future::ok(())
            })
    }

    /// Handle the stream of connection statuses.
    fn handle_connection_status(&self, connnection_status_rx: mpsc::UnboundedReceiver<(PublicKey, bool)>) -> impl Future<Item = (), Error = Error> + Send {
        let friends = self.friends.clone();
        connnection_status_rx
            .map_err(|()| -> Error { unreachable!("rx can't fail") })
            .for_each(move |(real_pk, status)| {
                if let Some(friend) = friends.write().get_mut(&real_pk) {
                    info!("Connection with a friend is {}", if status { "established" } else { "lost" });

                    friend.connected = status;
                }

                future::ok(())
            })
    }

    /// Send some of our relays to a friend and start using these relays to
    /// connect to this friend.
    fn share_relays(&self, friend_pk: PublicKey) -> impl Future<Item = (), Error = Error> + Send {
        let relays = self.tcp_connections.get_random_relays(MAX_SHARED_RELAYS as u8);
        if !relays.is_empty() {
            let relay_futures = relays.iter().map(|relay|
                self.tcp_connections.add_connection(relay.pk, friend_pk)
                    .map_err(|e| Error::new(ErrorKind::Other, e.compat()))
            ).collect::<Vec<_>>();

            let share_relays = ShareRelays {
                nodes: relays,
            };
            let mut buf = vec![0; 154];
            share_relays.to_bytes((&mut buf, 0)).unwrap();
            let send_future = self.net_crypto.send_lossless(friend_pk, buf)
                .map_err(|e| Error::new(ErrorKind::Other, e.compat()));

            Either::A(future::join_all(relay_futures).join(send_future).map(|_| ()))
        } else {
            Either::B(future::ok(()))
        }
    }

    fn main_loop(&self) -> impl Future<Item = (), Error = Error> + Send {
        let mut futures = Vec::new();

        for friend in self.friends.write().values_mut() {
            if friend.connected {
                // TODO: check ping

                if clock_elapsed(friend.ping_sent_time) >= FRIEND_PING_INTERVAL {
                    let future = self.net_crypto.send_lossless(friend.real_pk, vec![PACKET_ID_ALIVE])
                        .map_err(|e| Error::new(ErrorKind::Other, e.compat()));
                    futures.push(Either::A(future));
                    friend.ping_sent_time = clock_now();
                }

                futures.push(Either::B(self.share_relays(friend.real_pk)));
            } else {
                if friend.dht_pk_time.map_or(false, |time| clock_elapsed(time) >= FRIEND_DHT_TIMEOUT) {
                    if let Some(dht_pk) = friend.dht_pk {
                        self.dht.remove_friend(dht_pk);
                    }
                    friend.dht_pk = None;
                    friend.dht_pk_time = None;
                }

                if friend.saddr_time.map_or(false, |time| clock_elapsed(time) >= FRIEND_DHT_TIMEOUT) {
                    friend.saddr = None;
                    friend.saddr_time = None;
                }

                if let Some(dht_pk) = friend.dht_pk {
                    self.net_crypto.add_connection(friend.real_pk, dht_pk);
                    if let Some(saddr) = friend.saddr {
                        self.net_crypto.set_friend_udp_addr(friend.real_pk, saddr);
                    }
                }
            }
        }

        future::join_all(futures)
            .map(|_| ())
    }

    fn run_main_loop(self) -> impl Future<Item = (), Error = Error> + Send {
        let wakeups = Interval::new(Instant::now(), MAIN_LOOP_INTERVAL);
        wakeups
            .map_err(|e| Error::new(ErrorKind::Other, e))
            .for_each(move |_instant| {
                self.main_loop().timeout(MAIN_LOOP_INTERVAL).then(|res| {
                    if let Err(e) = res {
                        warn!("Failed to send friend's periodical packets: {}", e);
                        if let Some(e) = e.into_inner() {
                            return future::err(e)
                        }
                    }
                    future::ok(())
                })
            })
    }

    pub fn run(self) -> impl Future<Item = (), Error = Error> + Send {
        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        self.onion_client.set_dht_pk_sink(dht_pk_tx.clone());
        self.net_crypto.set_dht_pk_sink(dht_pk_tx);

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        self.dht.set_friend_saddr_sink(friend_saddr_tx);

        let (connection_status_tx, connection_status_rx) = mpsc::unbounded();
        self.net_crypto.set_connection_status_sink(connection_status_tx);

        let dht_pk_future = self.handle_dht_pk(dht_pk_rx);
        let friend_saddr_future = self.handle_friend_saddr(friend_saddr_rx);
        let connection_status_future = self.handle_connection_status(connection_status_rx);
        let main_loop_future = self.run_main_loop();

        future::select_all(vec![
            Box::new(dht_pk_future) as Box<dyn Future<Item=_, Error=_> + Send>,
            Box::new(friend_saddr_future),
            Box::new(connection_status_future),
            Box::new(main_loop_future),
        ]).map(|_| ()).map_err(|(e, _, _)| e)
    }
}
