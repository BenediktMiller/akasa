use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lazy_static::lazy_static;
use parking_lot::RwLock;
use rand::{rngs::OsRng, RngCore};

use crate::state::{ClientId, Executor, GlobalState, InternalMessage};

lazy_static! {
    pub static ref SIP24_QOS2_KEY: [u8; 16] = {
        let mut os_rng = OsRng::default();
        let mut key = [0u8; 16];
        os_rng.fill_bytes(&mut key);
        key
    };
}

pub(crate) fn start_keep_alive_timer<E: Executor>(
    keep_alive: u16,
    client_id: ClientId,
    last_packet_time: &Arc<RwLock<Instant>>,
    executor: &E,
    global: &Arc<GlobalState>,
) -> io::Result<()> {
    // FIXME: if kee_alive is zero, set a default keep_alive value from config
    if keep_alive > 0 {
        let half_interval = Duration::from_millis(keep_alive as u64 * 500);
        log::debug!("{} keep alive: {:?}", client_id, half_interval * 2);
        let last_packet_time = Arc::clone(last_packet_time);
        let global = Arc::clone(global);
        if let Err(err) = executor.spawn_interval(move || {
            // Need clone twice: https://stackoverflow.com/a/68462908/1274372
            let last_packet_time = Arc::clone(&last_packet_time);
            let global = Arc::clone(&global);
            async move {
                {
                    let last_packet_time = last_packet_time.read();
                    if last_packet_time.elapsed() <= half_interval * 3 {
                        return Some(half_interval);
                    }
                }
                // timeout, kick it out
                if let Some(sender) = global.get_client_sender(&client_id) {
                    let msg = InternalMessage::Kick {
                        reason: "timeout".to_owned(),
                    };
                    if let Err(err) = sender.send_async((client_id, msg)).await {
                        log::warn!(
                            "send timeout kick message to {:?} error: {:?}",
                            client_id,
                            err
                        );
                    }
                }
                None
            }
        }) {
            log::error!("spawn executor keep alive timer failed: {:?}", err);
            return Err(err);
        }
    }
    Ok(())
}
