use std::cmp;
use std::io::{self, IoSlice};
use std::mem;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use flume::bounded;
use futures_lite::io::{AsyncRead, AsyncWrite};
use futures_sink::Sink;
use mqtt_proto::{v3, v5};
use tokio::{
    sync::mpsc::{channel, error::TryRecvError, Receiver, Sender},
    task::JoinHandle,
};
use tokio_util::sync::PollSender;

use crate::config::Config;
use crate::hook::{Hook, HookConnectCode, HookConnectedAction, HookPublishCode, HookService};
use crate::server::{handle_accept, rt_tokio::TokioExecutor};
use crate::state::GlobalState;
use crate::{SessionV3, SessionV5};

pub struct MockConnControl {
    pub chan_in: Sender<Vec<u8>>,
    pub chan_out: Receiver<Vec<u8>>,
    pub global: Arc<GlobalState>,
}

pub struct MockConn {
    pub bind: SocketAddr,
    pub peer: SocketAddr,
    data_in: Vec<u8>,
    chan_in: Receiver<Vec<u8>>,
    chan_out: PollSender<Vec<u8>>,
}

impl MockConn {
    pub fn new_with_global(port: u16, global: Arc<GlobalState>) -> (MockConn, MockConnControl) {
        let (in_tx, in_rx) = channel(1);
        let (out_tx, out_rx) = channel(1);
        let conn = MockConn {
            bind: global.bind,
            peer: format!("127.0.0.1:{}", port).parse().unwrap(),
            data_in: Vec::new(),
            chan_in: in_rx,
            chan_out: PollSender::new(out_tx),
        };
        let control = MockConnControl {
            chan_in: in_tx,
            chan_out: out_rx,
            global,
        };
        (conn, control)
    }

    pub fn new(port: u16, config: Config) -> (MockConn, MockConnControl) {
        let bind = "127.0.0.1:1883".parse().unwrap();
        let global = Arc::new(GlobalState::new(bind, config));
        Self::new_with_global(port, global)
    }

    pub fn start_with_global(
        port: u16,
        global: Arc<GlobalState>,
    ) -> (JoinHandle<io::Result<()>>, MockConnControl) {
        let (conn, control) = Self::new_with_global(port, global);
        let task = control.start(conn);
        (task, control)
    }

    pub fn start(port: u16, config: Config) -> (JoinHandle<io::Result<()>>, MockConnControl) {
        let (conn, control) = Self::new(port, config);
        let task = control.start(conn);
        (task, control)
    }
}

impl MockConnControl {
    pub fn start(&self, conn: MockConn) -> JoinHandle<io::Result<()>> {
        let peer = conn.peer;
        let executor = Arc::new(TokioExecutor {});
        let global = Arc::clone(&self.global);

        let hook_handler = TestHook;
        let (hook_sender, hook_receiver) = bounded(2);
        let hook_service = HookService::new(
            Arc::clone(&executor),
            hook_handler,
            hook_receiver,
            Arc::clone(&global),
        );
        tokio::spawn(hook_service.start());
        tokio::spawn(handle_accept(conn, peer, hook_sender, executor, global))
    }

    pub fn try_read_packet_is_empty(&mut self) -> bool {
        self.chan_out.try_recv() == Err(TryRecvError::Empty)
    }

    pub async fn write_data(&self, data: Vec<u8>) {
        self.chan_in.send(data).await.unwrap();
    }
}

impl AsyncRead for MockConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // let peer = self.peer.clone();
        if self.data_in.is_empty() {
            self.data_in = match self.chan_in.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(v)) => v,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                }
            };
        }
        if self.data_in.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let amt = cmp::min(buf.len(), self.data_in.len());
        let mut other = self.data_in.split_off(amt);
        mem::swap(&mut other, &mut self.data_in);
        buf[..amt].copy_from_slice(&other);
        Poll::Ready(Ok(amt))
    }
}

impl AsyncWrite for MockConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let peer = self.peer.clone();
        let mut sink = Pin::new(&mut self.chan_out);
        match sink.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                log::debug!("send to [{}]", peer);
                if let Err(_) = sink.as_mut().start_send(buf.to_vec()) {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
                match sink.as_mut().poll_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => {}
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                    }
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            Poll::Pending => {
                log::debug!("[{}] MockConn poll_write() Pending", peer);
                Poll::Pending
            }
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut nwritten = 0;
        for buf in bufs {
            nwritten += match Pin::new(&mut *self).poll_write(cx, buf) {
                Poll::Pending => {
                    if nwritten > 0 {
                        return Poll::Ready(Ok(nwritten));
                    } else {
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Ok(len)) => len,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
        Poll::Ready(Ok(nwritten))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.chan_out)
            .as_mut()
            .poll_flush(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.chan_out)
            .as_mut()
            .poll_close(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

#[derive(Clone)]
pub struct TestHook;

#[async_trait]
impl Hook for TestHook {
    // =========================
    // ==== MQTT v5.x hooks ====
    // =========================

    async fn v5_before_connect(&self, connect: &v5::Connect) -> HookConnectCode {
        log::debug!("v5_before_connect(), identifier={}", connect.client_id);
        HookConnectCode::Success
    }

    async fn v5_after_connect(
        &self,
        session: &SessionV5,
        session_present: bool,
    ) -> Vec<HookConnectedAction> {
        log::debug!(
            "v5_after_connect(), [{}], identifier={}, session_present={}",
            session.client_id(),
            session.client_identifier(),
            session_present
        );
        Vec::new()
    }

    async fn v5_before_publish(
        &self,
        session: &SessionV5,
        publish: &v5::Publish,
    ) -> HookPublishCode {
        log::debug!(
            "v5_before_publish() [{}], topic={}",
            session.client_id(),
            publish.topic_name
        );
        HookPublishCode::Success
    }

    async fn v5_before_subscribe(
        &self,
        session: &SessionV5,
        subscribe: v5::Subscribe,
    ) -> v5::Subscribe {
        log::debug!(
            "v5_before_subscribe() [{}], {:#?}",
            session.client_id(),
            subscribe
        );
        subscribe
    }

    async fn v5_after_subscribe(
        &self,
        session: &SessionV5,
        _subscribe: v5::Subscribe,
        _reason_codes: Option<Vec<v5::SubscribeReasonCode>>,
    ) {
        log::debug!("v5_after_subscribe(), [{}]", session.client_id());
    }

    async fn v5_before_unsubscribe(&self, session: &SessionV5, unsubscribe: &v5::Unsubscribe) {
        log::debug!(
            "v5_before_unsubscribe(), [{}], {:#?}",
            session.client_id(),
            unsubscribe
        );
    }

    async fn v5_after_unsubscribe(&self, session: &SessionV5, _unsubscribe: v5::Unsubscribe) {
        log::debug!("v5_after_unsubscribe(), [{}]", session.client_id());
    }

    // =========================
    // ==== MQTT v3.x hooks ====
    // =========================

    async fn v3_before_connect(&self, connect: &v3::Connect) -> HookConnectCode {
        log::debug!("v3_before_connect(), identifier={}", connect.client_id);
        HookConnectCode::Success
    }

    async fn v3_after_connect(
        &self,
        session: &SessionV3,
        session_present: bool,
    ) -> Vec<HookConnectedAction> {
        log::debug!(
            "v3_after_connect(), [{}], identifier={}, session_present={}",
            session.client_id(),
            session.client_identifier(),
            session_present
        );
        Vec::new()
    }

    async fn v3_before_publish(
        &self,
        session: &SessionV3,
        publish: &v3::Publish,
    ) -> HookPublishCode {
        log::debug!(
            "v3_before_publish() [{}], topic={}",
            session.client_id(),
            publish.topic_name
        );
        HookPublishCode::Success
    }

    async fn v3_before_subscribe(
        &self,
        session: &SessionV3,
        subscribe: v3::Subscribe,
    ) -> v3::Subscribe {
        log::debug!(
            "v3_before_subscribe() [{}], {:#?}",
            session.client_id(),
            subscribe
        );
        subscribe
    }

    async fn v3_after_subscribe(
        &self,
        session: &SessionV3,
        _subscribe: v3::Subscribe,
        _codes: Option<Vec<v3::SubscribeReturnCode>>,
    ) {
        log::debug!("v3_after_subscribe(), [{}]", session.client_id());
    }

    async fn v3_before_unsubscribe(&self, session: &SessionV3, unsubscribe: &v3::Unsubscribe) {
        log::debug!(
            "v3_before_unsubscribe(), [{}], {:#?}",
            session.client_id(),
            unsubscribe
        );
    }

    async fn v3_after_unsubscribe(&self, session: &SessionV3, _unsubscribe: v3::Unsubscribe) {
        log::debug!("v3_after_unsubscribe(), [{}]", session.client_id());
    }
}
