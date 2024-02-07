use std::{ffi::CString, fmt::Debug, mem::MaybeUninit, ptr::null};

use anyhow::Result;
use ctru::{error::*, prelude::*, services::gfx::Swap};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SendFlags: u8 {
        const Default = ctru_sys::UDS_SENDFLAG_Default as u8;
        const Broadcast = ctru_sys::UDS_SENDFLAG_Broadcast as u8;
    }
}

#[doc(alias = "udsConnectionType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectionType {
    /// Client.
    Client = ctru_sys::UDSCONTYPE_Client,
    /// Spectator.
    Spectator = ctru_sys::UDSCONTYPE_Spectator,
}

impl From<ConnectionType> for u8 {
    fn from(value: ConnectionType) -> Self {
        value as Self
    }
}

impl TryFrom<u8> for ConnectionType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value as u32 {
            ctru_sys::UDSCONTYPE_Client => Ok(Self::Client),
            ctru_sys::UDSCONTYPE_Spectator => Ok(Self::Spectator),
            _ => Err(()),
        }
    }
}

#[doc(alias = "udsNodeInfo")]
#[derive(Debug)]
pub struct NodeInfo {
    pub uds_friendcodeseed: u64,
    pub username: String,
    pub unk_x1c: u16,
    pub flag: u8,
    pub pad_x1f: u8,
    pub node_id: u16,
    pub pad_x22: u16,
    pub word_x24: u32,
}

impl From<ctru_sys::udsNodeInfo> for NodeInfo {
    fn from(value: ctru_sys::udsNodeInfo) -> Self {
        unsafe {
            Self {
                uds_friendcodeseed: value.uds_friendcodeseed,
                username: String::from_utf16_lossy(
                    &value.__bindgen_anon_1.__bindgen_anon_1.username,
                ),
                unk_x1c: value.__bindgen_anon_1.__bindgen_anon_1.unk_x1c,
                flag: value.__bindgen_anon_1.__bindgen_anon_1.flag,
                pad_x1f: value.__bindgen_anon_1.__bindgen_anon_1.pad_x1f,
                node_id: value.NetworkNodeID,
                pad_x22: value.pad_x22,
                word_x24: value.word_x24,
            }
        }
    }
}

#[doc(alias = "udsNetworkScanInfo")]
#[derive(Debug)]
pub struct NetworkScanInfo {
    pub datareply_entry: ctru_sys::nwmBeaconDataReplyEntry,
    pub network: ctru_sys::udsNetworkStruct,
    pub nodes: Vec<NodeInfo>,
}

impl From<ctru_sys::udsNetworkScanInfo> for NetworkScanInfo {
    fn from(value: ctru_sys::udsNetworkScanInfo) -> Self {
        Self {
            datareply_entry: value.datareply_entry,
            network: value.network,
            nodes: value
                .nodes
                .into_iter()
                .filter_map(|n| {
                    if n.uds_friendcodeseed != 0 {
                        Some(n.into())
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}

// Handle to the UDS service
pub struct Uds {
    connected: bool,
    context: Option<ctru_sys::udsBindContext>,
    network: Option<ctru_sys::udsNetworkStruct>,
}

impl Uds {
    // size of one frame
    const RECV_FRAME_SIZE: usize = ctru_sys::UDS_DATAFRAME_MAXSIZE as usize;

    // max dataframe size * 8
    const RECV_BUF_SIZE: u32 = ctru_sys::UDS_DEFAULT_RECVBUFSIZE;

    // must be slightly larger than the total recv_buffer_size
    const SHAREDMEM_SIZE: usize = 0x3000;

    // devkitpro example uses this size
    const SCAN_BUF_SIZE: usize = 0x4000;

    // maximum number of devices that can be connected to the network
    const MAX_NODES: u8 = ctru_sys::UDS_MAXNODES as u8;

    // field in struct
    const MAX_APPDATA_SIZE: usize = 200;

    #[doc(alias = "udsInit")]
    pub fn new(username: Option<&str>) -> ctru::Result<Self> {
        ResultCode(match username {
            Some(s) => {
                let cstr = CString::new(s);
                match cstr {
                    Ok(c) => unsafe { ctru_sys::udsInit(Self::SHAREDMEM_SIZE, c.as_ptr()) },
                    Err(_) => unsafe { ctru_sys::udsInit(Self::SHAREDMEM_SIZE, null()) },
                }
            }
            None => unsafe { ctru_sys::udsInit(Self::SHAREDMEM_SIZE, null()) },
        })?;
        Ok(Uds {
            connected: false,
            context: None,
            network: None,
        })
    }

    #[doc(alias = "udsScanBeacons")]
    pub fn scan(
        &self,
        comm_id: &[u8; 4],
        additional_id: Option<u8>,
        whitelist_macaddr: Option<macaddr::MacAddr6>,
    ) -> ctru::Result<Vec<NetworkScanInfo>> {
        let mut scan_buf = MaybeUninit::<[u8; Self::SCAN_BUF_SIZE]>::zeroed();

        let mut networks = MaybeUninit::uninit();
        let mut total_networks = MaybeUninit::uninit();

        ResultCode(unsafe {
            ctru_sys::udsScanBeacons(
                scan_buf.as_mut_ptr().cast(),
                Self::SCAN_BUF_SIZE,
                networks.as_mut_ptr(),
                total_networks.as_mut_ptr(),
                u32::from_be_bytes(*comm_id),
                additional_id.unwrap_or(0),
                whitelist_macaddr
                    .map(|m| m.as_bytes().as_ptr())
                    .unwrap_or(null()),
                self.connected,
            )
        })?;

        unsafe {
            scan_buf.assume_init_drop();
        }

        let networks = unsafe { networks.assume_init() };
        let total_networks = unsafe { total_networks.assume_init() };

        let networks = if total_networks > 0 {
            unsafe { Vec::from_raw_parts(networks, total_networks, total_networks) }
                .into_iter()
                .map(<_ as Into<NetworkScanInfo>>::into)
                .collect()
        } else {
            vec![]
        };

        Ok(networks)
    }

    #[doc(alias = "udsGetNetworkStructApplicationData")]
    pub fn get_network_appdata(
        &self,
        network: &NetworkScanInfo,
        max_size: Option<usize>,
    ) -> ctru::Result<Vec<u8>> {
        // field in struct
        const MAX_APPDATA_SIZE: usize = 200;

        let mut appdata_buffer =
            vec![0u8; max_size.unwrap_or(MAX_APPDATA_SIZE).min(MAX_APPDATA_SIZE)];

        let mut actual_size = MaybeUninit::uninit();

        ResultCode(unsafe {
            ctru_sys::udsGetNetworkStructApplicationData(
                &network.network as *const _,
                appdata_buffer.as_mut_ptr().cast(),
                appdata_buffer.len(),
                actual_size.as_mut_ptr(),
            )
        })?;

        let actual_size = unsafe { actual_size.assume_init() };

        Ok(appdata_buffer[..actual_size].to_vec())
    }

    #[doc(alias = "udsGetApplicationData")]
    pub fn get_appdata(&self, max_size: Option<usize>) -> ctru::Result<Vec<u8>> {
        let mut appdata_buffer = vec![
            0u8;
            max_size
                .unwrap_or(Self::MAX_APPDATA_SIZE)
                .min(Self::MAX_APPDATA_SIZE)
        ];

        let mut actual_size = MaybeUninit::uninit();

        ResultCode(unsafe {
            ctru_sys::udsGetApplicationData(
                appdata_buffer.as_mut_ptr().cast(),
                appdata_buffer.len(),
                actual_size.as_mut_ptr(),
            )
        })?;

        let actual_size = unsafe { actual_size.assume_init() };

        Ok(appdata_buffer[..actual_size].to_vec())
    }

    #[doc(alias = "udsConnectNetwork")]
    pub fn connect_network(
        &mut self,
        network: &NetworkScanInfo,
        passphrase: &[u8],
        connection_type: ConnectionType,
        channel: u8,
    ) -> ctru::Result<()> {
        let mut context = MaybeUninit::uninit();

        ResultCode(unsafe {
            ctru_sys::udsConnectNetwork(
                &network.network as *const _,
                passphrase.as_ptr().cast(),
                passphrase.len(),
                context.as_mut_ptr(),
                ctru_sys::UDS_BROADCAST_NETWORKNODEID as u16,
                connection_type as u32,
                channel,
                Self::RECV_BUF_SIZE,
            )
        })?;

        self.connected = true;

        let context = unsafe { context.assume_init() };

        self.context.replace(context);

        Ok(())
    }

    #[doc(alias = "udsDisconnectNetwork")]
    pub fn disconnect_network(&mut self) -> ctru::Result<()> {
        if !self.connected {
            return Err(ctru::Error::Other("not connected to any network".into()));
        }

        if self.context.is_some() {
            self.unbind_context()?;
        }

        ResultCode(unsafe { ctru_sys::udsDisconnectNetwork() })?;

        self.connected = false;

        Ok(())
    }

    #[doc(alias = "udsUnbind")]
    pub fn unbind_context(&mut self) -> ctru::Result<()> {
        if let Some(mut ctx) = self.context {
            ResultCode(unsafe { ctru_sys::udsUnbind(&mut ctx as *mut _) })?;
        } else {
            return Err(ctru::Error::Other("no context currently bound".into()));
        }

        self.context = None;

        Ok(())
    }

    #[doc(alias = "udsGetChannel")]
    pub fn get_channel(&self) -> ctru::Result<u8> {
        if !self.connected && self.network.is_none() {
            return Err(ctru::Error::Other("not connected to any network".into()));
        }

        let mut channel = MaybeUninit::uninit();

        ResultCode(unsafe { ctru_sys::udsGetChannel(channel.as_mut_ptr()) })?;

        let channel = unsafe { channel.assume_init() };

        Ok(channel)
    }

    #[doc(alias = "udsWaitConnectionStatusEvent")]
    pub fn wait_status_event(&self, next: bool, wait: bool) -> ctru::Result<bool> {
        if !self.connected && self.network.is_none() {
            return Err(ctru::Error::Other("not connected to any network".into()));
        }
        Ok(unsafe { ctru_sys::udsWaitConnectionStatusEvent(next, wait) })
    }

    #[doc(alias = "udsGetConnectionStatus")]
    pub fn get_connection_status(&self) -> ctru::Result<ctru_sys::udsConnectionStatus> {
        let mut status = MaybeUninit::uninit();

        ResultCode(unsafe { ctru_sys::udsGetConnectionStatus(status.as_mut_ptr()) })?;

        let status = unsafe { status.assume_init() };
        Ok(status)
    }

    #[doc(alias = "udsSendTo")]
    pub fn send_packet(
        &self,
        packet: &[u8],
        to_nodes: u16,
        channel: u8,
        flags: SendFlags,
    ) -> ctru::Result<()> {
        if (!self.connected || self.context.is_none()) && self.network.is_none() {
            return Err(ctru::Error::Other("not connected to any network".into()));
        }

        if self.context.unwrap().spectator {
            return Err(ctru::Error::Other("cannot send data as a spectator".into()));
        }

        let code = ResultCode(unsafe {
            ctru_sys::udsSendTo(
                to_nodes,
                channel,
                flags.bits(),
                packet.as_ptr().cast(),
                packet.len(),
            )
        });

        if code.0
            != ctru_sys::MAKERESULT(
                ctru_sys::RL_STATUS as _,
                ctru_sys::RS_OUTOFRESOURCE as _,
                ctru_sys::RM_UDS as _,
                ctru_sys::RD_BUSY as _,
            )
        {
            code?;
        }

        Ok(())
    }

    #[doc(alias = "udsPullPacket")]
    pub fn pull_packet(&self) -> ctru::Result<Option<(Vec<u8>, u16)>> {
        if (!self.connected || self.context.is_none()) && self.network.is_none() {
            return Err(ctru::Error::Other("not connected to any network".into()));
        }

        let mut frame = MaybeUninit::<[u8; Self::RECV_FRAME_SIZE]>::zeroed();

        let mut actual_size = MaybeUninit::uninit();
        let mut src_node_id = MaybeUninit::uninit();

        ResultCode(unsafe {
            ctru_sys::udsPullPacket(
                &self.context.unwrap() as *const _,
                frame.as_mut_ptr().cast(),
                Self::RECV_FRAME_SIZE,
                actual_size.as_mut_ptr(),
                src_node_id.as_mut_ptr(),
            )
        })?;

        let frame = unsafe { frame.assume_init() };
        let actual_size = unsafe { actual_size.assume_init() };
        let src_node_id = unsafe { src_node_id.assume_init() };

        Ok(if actual_size == 0 {
            None
        } else {
            Some((frame[..actual_size].to_vec(), src_node_id))
        })
    }

    #[doc(alias = "udsCreateNetwork")]
    pub fn create_network(
        &mut self,
        comm_id: &[u8; 4],
        additional_id: Option<u8>,
        max_nodes: Option<u8>,
        passphrase: &[u8],
        channel: u8,
    ) -> ctru::Result<()> {
        let mut network = MaybeUninit::uninit();
        unsafe {
            ctru_sys::udsGenerateDefaultNetworkStruct(
                network.as_mut_ptr(),
                u32::from_be_bytes(*comm_id),
                additional_id.unwrap_or(0),
                max_nodes.unwrap_or(Self::MAX_NODES).min(Self::MAX_NODES),
            )
        };

        let network = unsafe { network.assume_init() };

        self.network.replace(network);

        let mut context = MaybeUninit::uninit();

        ResultCode(unsafe {
            ctru_sys::udsCreateNetwork(
                &network as *const _,
                passphrase.as_ptr().cast(),
                passphrase.len(),
                context.as_mut_ptr(),
                channel,
                Self::RECV_BUF_SIZE,
            )
        })?;

        let context = unsafe { context.assume_init() };

        self.context.replace(context);

        Ok(())
    }

    #[doc(alias = "udsDestroyNetwork")]
    pub fn destroy_network(&mut self) -> ctru::Result<()> {
        if self.network.is_none() {
            return Err(ctru::Error::Other("no network created".into()));
        }

        if self.context.is_some() {
            self.unbind_context()?;
        }

        ResultCode(unsafe { ctru_sys::udsDestroyNetwork() })?;

        self.network = None;

        Ok(())
    }

    #[doc(alias = "udsSetApplicationData")]
    pub fn set_appdata(&self, data: &[u8]) -> ctru::Result<()> {
        if data.len() > Self::MAX_APPDATA_SIZE {
            return Err(ctru::Error::BufferTooShort {
                provided: data.len(),
                wanted: Self::MAX_APPDATA_SIZE,
            });
        }

        ResultCode(unsafe { ctru_sys::udsSetApplicationData(data.as_ptr().cast(), data.len()) })?;

        Ok(())
    }
}

impl Drop for Uds {
    #[doc(alias = "udsExit")]
    fn drop(&mut self) {
        if self.connected {
            self.disconnect_network().unwrap();
        }
        if self.network.is_some() {
            self.destroy_network().unwrap();
        }
        unsafe { ctru_sys::udsExit() };
    }
}

/*#[no_mangle]
unsafe extern "C" fn __appInit() {
    ctru_sys::srvInit();
}*/

fn main() -> Result<()> {
    let apt = Apt::new().unwrap();
    let mut hid = Hid::new().unwrap();
    let gfx = Gfx::new().unwrap();
    let console = Console::new(gfx.top_screen.borrow_mut());

    /*let mut soc = Soc::new().unwrap();
    soc.redirect_to_3dslink(true, true).unwrap();*/

    println!("Local networking demo");

    let mut uds = Uds::new(None).unwrap();

    println!("UDS initialised");

    enum State {
        Initialised,
        Scanning,
        DrawList,
        List,
        Connect,
        Connected,
        Create,
        Created,
    }

    let mut state = State::Initialised;

    println!("Press A to start scanning or B to create a new network");

    let mut networks = vec![];
    let mut selected_network = 0;

    let mut mode = ConnectionType::Client;

    let mut channel = 0;
    let data_channel = 1;

    while apt.main_loop() {
        gfx.wait_for_vblank();

        hid.scan_input();
        if hid.keys_down().contains(KeyPad::START) {
            break;
        }

        match state {
            State::Initialised => {
                if hid.keys_down().contains(KeyPad::A) {
                    state = State::Scanning;
                    console.clear();
                } else if hid.keys_down().contains(KeyPad::B) {
                    state = State::Create;
                    console.clear();
                }
            }
            State::Scanning => {
                println!("Scanning...");

                let nwks = uds.scan(b"HBW\x10", None, None);

                match nwks {
                    Ok(n) => {
                        networks = n;
                        selected_network = 0;
                        state = State::DrawList;
                    }
                    Err(e) => {
                        state = State::Initialised;
                        console.clear();
                        eprintln!("Error while scanning: {e}");
                        println!("Press A to start scanning or B to create a new network");
                    }
                }
            }
            State::DrawList => {
                console.clear();

                println!(
                    "Scanned successfully; {} network{} found",
                    networks.len(),
                    if networks.len() == 1 { "" } else { "s" }
                );

                println!("D-Pad to select, A to connect as client, R + A to connect as spectator, B to create a new network");

                for (index, n) in networks.iter().enumerate() {
                    println!(
                        "{} Username: {}",
                        if index == selected_network { ">" } else { " " },
                        n.nodes[0].username
                    );
                }

                state = State::List;
            }
            State::List => {
                if hid.keys_down().contains(KeyPad::UP) && selected_network > 0 {
                    selected_network -= 1;
                    state = State::DrawList;
                } else if hid.keys_down().contains(KeyPad::DOWN)
                    && selected_network < networks.len() - 1
                {
                    selected_network += 1;
                    state = State::DrawList;
                } else if hid.keys_down().contains(KeyPad::A) {
                    state = State::Connect;
                    mode = if hid.keys_held().contains(KeyPad::R) {
                        ConnectionType::Spectator
                    } else {
                        ConnectionType::Client
                    };
                } else if hid.keys_down().contains(KeyPad::B) {
                    state = State::Create;
                }
            }
            State::Connect => {
                let appdata = uds.get_network_appdata(&networks[selected_network], None)?;
                println!("App data: {:02X?}", appdata);

                if let Err(e) = uds.connect_network(
                    &networks[selected_network],
                    b"udsdemo passphrase c186093cd2652741\0",
                    mode,
                    data_channel,
                ) {
                    console.clear();
                    eprintln!("Error while connecting to network: {e}");
                    state = State::Initialised;
                    println!("Press A to start scanning or B to create a new network");
                } else {
                    channel = uds.get_channel()?;
                    println!("Connected using channel {}", channel);

                    let appdata = uds.get_appdata(None)?;
                    println!("App data: {:02X?}", appdata);

                    if uds.wait_status_event(false, false)? {
                        println!("Connection status event signalled");
                        let status = uds.get_connection_status()?;
                        println!("Status: {status:#02X?}");
                    }

                    println!("Press A to stop data transfer");
                    state = State::Connected;
                }
            }
            State::Connected => {
                let packet = uds.pull_packet();

                match packet {
                    Ok(p) => {
                        if let Some((pkt, node)) = p {
                            println!(
                                "{:02X}{:02X}{:02X}{:02X} from {:04X}",
                                pkt[0], pkt[1], pkt[2], pkt[3], node
                            );
                        }

                        if uds.wait_status_event(false, false)? {
                            println!("Connection status event signalled");
                            let status = uds.get_connection_status()?;
                            println!("Status: {status:#02X?}");
                        }

                        if hid.keys_down().contains(KeyPad::A) {
                            uds.disconnect_network()?;
                            state = State::Initialised;
                            console.clear();
                            println!("Press A to start scanning or B to create a new network");
                        } else if !hid.keys_down().is_empty() || !hid.keys_up().is_empty() {
                            let transfer_data = hid.keys_held().bits();
                            if mode != ConnectionType::Spectator {
                                uds.send_packet(
                                    &transfer_data.to_le_bytes(),
                                    ctru_sys::UDS_BROADCAST_NETWORKNODEID as _,
                                    data_channel,
                                    SendFlags::Default,
                                )?;
                            }
                        }
                    }
                    Err(e) => {
                        uds.disconnect_network()?;
                        console.clear();
                        eprintln!("Error while grabbing packet from network: {e}");
                        state = State::Initialised;
                        println!("Press A to start scanning or B to create a new network");
                    }
                }
            }
            State::Create => {
                console.clear();
                println!("Creating network...");

                match uds.create_network(
                    b"HBW\x10",
                    None,
                    None,
                    b"udsdemo passphrase c186093cd2652741\0",
                    data_channel,
                ) {
                    Ok(_) => {
                        let appdata = [0x69u8, 0x8a, 0x05, 0x5c]
                            .into_iter()
                            .chain((*b"Test appdata.").into_iter())
                            .chain(std::iter::repeat(0).take(3))
                            .collect::<Vec<_>>();

                        uds.set_appdata(&appdata).unwrap();

                        println!("Press A to stop data transfer");
                        state = State::Created;
                    }
                    Err(e) => {
                        console.clear();
                        eprintln!("Error while creating network: {e}");
                        state = State::Initialised;
                        println!("Press A to start scanning or B to create a new network");
                    }
                }
            }
            State::Created => {
                let packet = uds.pull_packet();

                match packet {
                    Ok(p) => {
                        if let Some((pkt, node)) = p {
                            println!(
                                "{:02X}{:02X}{:02X}{:02X} from {:04X}",
                                pkt[0], pkt[1], pkt[2], pkt[3], node
                            );
                        }

                        if uds.wait_status_event(false, false)? {
                            println!("Connection status event signalled");
                            let status = uds.get_connection_status()?;
                            println!("Status: {status:#02X?}");
                        }

                        if hid.keys_down().contains(KeyPad::A) {
                            uds.destroy_network()?;
                            state = State::Initialised;
                            console.clear();
                            println!("Press A to start scanning or B to create a new network");
                        } else if !hid.keys_down().is_empty() || !hid.keys_up().is_empty() {
                            let transfer_data = hid.keys_held().bits();
                            uds.send_packet(
                                &transfer_data.to_le_bytes(),
                                ctru_sys::UDS_BROADCAST_NETWORKNODEID as _,
                                data_channel,
                                SendFlags::Default,
                            )?;
                        }
                    }
                    Err(e) => {
                        uds.destroy_network()?;
                        console.clear();
                        eprintln!("Error while grabbing packet from network: {e}");
                        state = State::Initialised;
                        println!("Press A to start scanning or B to create a new network");
                    }
                }
            }
        }
    }

    Ok(())
}
