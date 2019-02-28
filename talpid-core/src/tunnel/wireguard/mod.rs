use self::config::Config;
use super::{TunnelEvent, TunnelMetadata};
use crate::routing;
use std::{path::Path, sync::mpsc};

pub mod config;
mod ping_monitor;
pub mod wireguard_go;

pub use self::wireguard_go::WgGoTunnel;

// amount of seconds to run `ping` until it returns.
const PING_TIMEOUT: u16 = 5;

error_chain! {
    errors {
        /// Failed to setup a tunnel device
        SetupTunnelDeviceError {
            description("Failed to create tunnel device")
        }
        /// Failed to setup wireguard tunnel
        StartWireguardError(status: i32) {
            display("Failed to start wireguard tunnel - {}", status)
        }
        /// Failed to tear down wireguard tunnel
        StopWireguardError(status: i32) {
            display("Failed to stop wireguard tunnel - {}", status)
        }
        /// Failed to set up routing
        SetupRoutingError {
            display("Failed to setup routing")
        }
        /// Failed to move or craete a log file
        PrepareLogFileError {
            display("Failed to setup a logging file")
        }
        /// Tunnel interface name contained null bytes
        InterfaceNameError {
            display("Tunnel interface name contains null bytes")
        }
        /// Pinging timed out
        PingTimeoutError {
            display("Ping timed out")
        }
    }
}

/// Spawns and monitors a wireguard tunnel
pub struct WireguardMonitor {
    /// Tunnel implementation
    tunnel: Box<dyn Tunnel>,
    /// Route manager
    router: routing::RouteManager,
    /// Callback to signal tunnel events
    event_callback: Box<Fn(TunnelEvent) + Send + Sync + 'static>,
    close_msg_sender: mpsc::Sender<CloseMsg>,
    close_msg_receiver: mpsc::Receiver<CloseMsg>,
}

impl WireguardMonitor {
    pub fn start<F: Fn(TunnelEvent) + Send + Sync + 'static>(
        config: &Config,
        log_path: Option<&Path>,
        on_event: F,
    ) -> Result<WireguardMonitor> {
        let tunnel = Box::new(WgGoTunnel::start_tunnel(&config, log_path)?);
        let router = routing::RouteManager::new().chain_err(|| ErrorKind::SetupRoutingError)?;
        let event_callback = Box::new(on_event);
        let (close_msg_sender, close_msg_receiver) = mpsc::channel();
        let mut monitor = WireguardMonitor {
            tunnel,
            router,
            event_callback,
            close_msg_sender,
            close_msg_receiver,
        };
        monitor.setup_routing(&config)?;
        monitor.start_pinger(&config);
        monitor.tunnel_up(&config);

        ping_monitor::ping(
            config.gateway,
            PING_TIMEOUT,
            &monitor.tunnel.get_interface_name().to_string(),
        )
        .chain_err(|| ErrorKind::PingTimeoutError)?;

        Ok(monitor)
    }

    pub fn close_handle(&self) -> CloseHandle {
        CloseHandle {
            chan: self.close_msg_sender.clone(),
        }
    }

    pub fn wait(mut self) -> Result<()> {
        let wait_result = match self.close_msg_receiver.recv() {
            Ok(CloseMsg::PingErr) => Err(ErrorKind::PingTimeoutError.into()),
            Ok(CloseMsg::Stop) => Ok(()),
            Err(_) => Ok(()),
        };

        // Clear routes manually - otherwise there will be some log spam since the tunnel device
        // can be removed before the routes are cleared, which automatically clears some of the
        // routes that were set.
        if let Err(e) = self.router.delete_routes() {
            log::error!("Failed to remove a route from the routing table - {}", e);
        }

        if let Err(e) = self.tunnel.stop() {
            log::error!("Failed to stop tunnel - {}", e);
        }
        (self.event_callback)(TunnelEvent::Down);
        wait_result
    }

    fn setup_routing(&mut self, config: &Config) -> Result<()> {
        let iface_name = self.tunnel.get_interface_name();
        let mut routes: Vec<_> = config
            .peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter())
            .cloned()
            .map(|allowed_ip| {
                routing::Route::new(allowed_ip, routing::NetNode::Device(iface_name.to_string()))
            })
            .collect();

        // To survive network roaming, we should listen for new routes and reapply them
        // here - probably would need RouteManager be extended. Or maybe RouteManager can deal
        // with it on it's own
        let default_node = self
            .router
            .get_default_route_node()
            .chain_err(|| ErrorKind::SetupRoutingError)?;

        // route endpoints with specific routes
        for peer in config.peers.iter() {
            let default_route = routing::Route::new(
                peer.endpoint.ip().into(),
                routing::NetNode::Address(default_node),
            );
            routes.push(default_route);
        }

        let required_routes = routing::RequiredRoutes { routes };

        self.router
            .add_routes(required_routes)
            .chain_err(|| ErrorKind::SetupRoutingError)
    }

    fn start_pinger(&self, config: &Config) {
        let close_sender = self.close_msg_sender.clone();

        ping_monitor::spawn_ping_monitor(
            config.gateway,
            PING_TIMEOUT,
            self.tunnel.get_interface_name().to_string(),
            move || {
                let _ = close_sender.send(CloseMsg::PingErr);
            },
        )
    }

    fn tunnel_up(&self, config: &Config) {
        let interface_name = self.tunnel.get_interface_name();
        let metadata = TunnelMetadata {
            interface: interface_name.to_string(),
            ips: config.tunnel.addresses.clone(),
            gateway: config.gateway,
        };
        (self.event_callback)(TunnelEvent::Up(metadata));
    }
}

enum CloseMsg {
    Stop,
    PingErr,
}

#[derive(Clone, Debug)]
pub struct CloseHandle {
    chan: mpsc::Sender<CloseMsg>,
}


impl CloseHandle {
    pub fn close(&mut self) {
        if let Err(e) = self.chan.send(CloseMsg::Stop) {
            log::trace!("Failed to send close message to wireguard tunnel - {}", e);
        }
    }
}

pub trait Tunnel: Send {
    fn get_interface_name(&self) -> &str;
    fn stop(self: Box<Self>) -> Result<()>;
}
