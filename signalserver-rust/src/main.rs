//! EasyRTC WebRTC 信令服务器 (Rust 重写版)
//!
//! 功能: 作为 WebSocket 信令服务器, 中转 WebRTC 的 Offer/Answer 信令,
//!       维护设备在线列表, 转发 STUN/TURN 配置, 验证 SDP 格式。
//!
//! 协议: 自定义二进制信令协议 (LE 编码, packed 结构) over WebSocket
//!
//! 端口: WS 默认 6688, WSS 默认 6689

mod config;
mod peer;
mod protocol;
mod sdp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn, error};

use config::StunTurnInfo;
use peer::*;
use protocol::*;
use sdp::is_valid_sdp;

/// 配置文件路径
const CONFIG_FILE: &str = "./signalserver.ini";
/// 自增连接 ID 生成器
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// 设置 TCP Keepalive, 心跳间隔 10 秒
fn set_keepalive(stream: &TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    let s = SockRef::from(stream);
    let _ = s.set_keepalive(true);
    let _ = s.set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(10)));
}

/// 处理单条 WebSocket 连接
///
/// 泛型参数 S 支持 TcpStream (WS) 和 TlsStream<TcpStream> (WSS)
async fn handle_ws_stream<S>(
    raw_stream: S,
    addr: SocketAddr,
    registry: PeerRegistry,
    stun_turn_info: Arc<StunTurnInfo>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws = match accept_async(raw_stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!("[{}] WebSocket 握手失败: {}", addr, e);
            return;
        }
    };
    info!("[{}] 已连接", addr);

    let (ws_writer, mut ws_reader) = ws.split();
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<Message>();
    let _writer_task = tokio::spawn(async move {
        let mut sink = ws_writer;
        while let Some(msg) = msg_rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let _msg_tx_reg = msg_tx.clone();
    let mut my_id: Option<[u32; 4]> = None;

    loop {
        tokio::select! {
            msg = ws_reader.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if let Err(e) = process_binary(
                            &data, conn_id, &mut my_id, &registry, &stun_turn_info, &msg_tx, addr,
                        ).await {
                            warn!("[{}] 处理消息失败: {}", addr, e);
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Ping(d))) => { let _ = msg_tx.send(Message::Pong(d)); }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        warn!("[{}] WebSocket 错误: {}", addr, e);
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    // 从注册表清理此连接
    let mut reg = registry.write().await;
    reg.retain(|_, h| h.conn_id != conn_id);
    info!("[{}] 已断开", addr);
}

/// 启动 WS 服务器 (明文 WebSocket)
fn serve_ws(
    port: u16,
    registry: PeerRegistry,
    stun_info: Arc<StunTurnInfo>,
) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            Ok(l) => l,
            Err(e) => {
                error!("WS 服务器绑定端口 {} 失败: {}", port, e);
                return;
            }
        };
        info!("WS 服务器已启动, 监听端口 {}", port);
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    set_keepalive(&stream);
                    let r = registry.clone();
                    let s = stun_info.clone();
                    tokio::spawn(async move {
                        handle_ws_stream(stream, addr, r, s).await;
                    });
                }
                Err(e) => error!("WS 接受连接失败: {}", e),
            }
        }
    });
}

/// 启动 WSS 服务器 (TLS 加密 WebSocket)
fn serve_wss(
    port: u16,
    cert_file: &str,
    key_file: &str,
    registry: PeerRegistry,
    stun_info: Arc<StunTurnInfo>,
) -> Result<()> {
    let certs = {
        let mut reader = std::io::BufReader::new(std::fs::File::open(cert_file)?);
        rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?
    };
    let key = {
        let mut reader = std::io::BufReader::new(std::fs::File::open(key_file)?);
        rustls_pemfile::private_key(&mut reader)?
            .ok_or_else(|| anyhow::anyhow!("{}: 未找到私钥", key_file))?
    };

    let tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("TLS 配置创建失败");
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));

    tokio::spawn(async move {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            Ok(l) => l,
            Err(e) => {
                error!("WSS 服务器绑定端口 {} 失败: {}", port, e);
                return;
            }
        };
        info!("WSS 服务器已启动, 监听端口 {}", port);
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    set_keepalive(&stream);
                    let acceptor = tls_acceptor.clone();
                    let r = registry.clone();
                    let s = stun_info.clone();
                    tokio::spawn(async move {
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("[{}] TLS 握手失败: {}", addr, e);
                                return;
                            }
                        };
                        handle_ws_stream(tls_stream, addr, r, s).await;
                    });
                }
                Err(e) => error!("WSS 接受连接失败: {}", e),
            }
        }
    });
    Ok(())
}

/// 分发二进制消息到对应的处理函数
async fn process_binary(
    data: &[u8],
    conn_id: u64,
    my_id: &mut Option<[u32; 4]>,
    registry: &PeerRegistry,
    stun_turn_info: &StunTurnInfo,
    tx: &mpsc::UnboundedSender<Message>,
    addr: SocketAddr,
) -> Result<()> {
    let header = parse_base(data).ok_or_else(|| anyhow::anyhow!("无效的消息头"))?;
    if (data.len() as u32) != header.length {
        return Err(anyhow::anyhow!("消息长度不匹配: 实际 {} vs 声明 {}", data.len(), header.length));
    }
    match header.msgtype {
        MSG_REQ_LOGIN => handle_login(data, conn_id, my_id, registry, tx, addr).await,
        MSG_REQ_CONNECT => handle_connect(data, conn_id, my_id, registry, stun_turn_info, tx, addr).await,
        MSG_NTI_OFFER => handle_offer(data, conn_id, my_id, registry, stun_turn_info, tx, addr).await,
        MSG_NTI_ANSWER => handle_answer(data, conn_id, my_id, registry, tx, addr).await,
        MSG_REQ_ONLINE => handle_online(conn_id, my_id, registry, tx, addr).await,
        _ => {
            warn!("[{}] 未知消息类型: 0x{:X}", addr, header.msgtype);
            Ok(())
        }
    }
}

/// 处理设备登录请求 (0x10001 -> 0x10002)
async fn handle_login(
    data: &[u8],
    conn_id: u64,
    my_id: &mut Option<[u32; 4]>,
    registry: &PeerRegistry,
    tx: &mpsc::UnboundedSender<Message>,
    addr: SocketAddr,
) -> Result<()> {
    let (req, _extra0, _extra1) =
        parse_req_login(data).ok_or_else(|| anyhow::anyhow!("登录消息解析失败"))?;
    if uuid_is_zero(&req.myid) {
        return Err(anyhow::anyhow!("UUID 全零, 拒绝登录"));
    }
    if REQ_LOGIN_SIZE + req.extradatalen0 as usize + req.extradatalen1 as usize != data.len() {
        return Err(anyhow::anyhow!("登录消息长度不匹配"));
    }

    let key = make_uuid_key(&req.myid);

    // 如果此 UUID 已在线, 踢掉旧连接
    {
        let mut reg = registry.write().await;
        if let Some(old) = reg.get(&key) {
            if old.conn_id != conn_id {
                let old_tx = old.sender.clone();
                let _ = old_tx.send(Message::Close(None));
            }
        }
        reg.insert(
            key,
            PeerHandle {
                conn_id,
                sender: tx.clone(),
                mykey: req.mykey,
                mysn: req.mysn,
                role: 1,
                alive: true,
                extradatalen0: req.extradatalen0,
                extradata0: _extra0.to_vec(),
            },
        );
    }

    *my_id = Some(req.myid);
    let ack = build_ack_login(&req.myid);
    let _ = tx.send(Message::Binary(ack.into()));

    info!(
        "[{}] 设备登录 UUID {:08X}-{:04X}-{:04X}-{:04X}-{:04X}{:08X}",
        addr,
        req.myid[0],
        req.myid[1] >> 16,
        req.myid[1] & 0xFFFF,
        req.myid[2] >> 16,
        req.myid[2] & 0xFFFF,
        req.myid[3]
    );
    Ok(())
}

/// 处理客户端连接请求 (0x10003 -> 0x10004 + 0x10005)
async fn handle_connect(
    data: &[u8],
    conn_id: u64,
    my_id: &mut Option<[u32; 4]>,
    registry: &PeerRegistry,
    stun_turn_info: &StunTurnInfo,
    tx: &mpsc::UnboundedSender<Message>,
    addr: SocketAddr,
) -> Result<()> {
    let (req, extra0, _extra1) =
        parse_req_connect(data).ok_or_else(|| anyhow::anyhow!("连接请求解析失败"))?;
    if REQ_CONNECT_SIZE + req.extradatalen0 as usize + req.extradatalen1 as usize != data.len() {
        return Err(anyhow::anyhow!("连接请求消息长度不匹配"));
    }

    // 纯客户端没有 UUID, 由信令服务器分配
    let client_uuid = if let Some(id) = my_id {
        *id
    } else {
        let new_id = generate_client_uuid();
        {
            let mut reg = registry.write().await;
            reg.insert(
                make_uuid_key(&new_id),
                PeerHandle {
                    conn_id,
                    sender: tx.clone(),
                    mykey: [0u8; 32],
                    mysn: [0u32; 4],
                    role: 2,
                    alive: true,
                    extradatalen0: 0,
                    extradata0: Vec::new(),
                },
            );
        }
        *my_id = Some(new_id);
        new_id
    };

    let target_key = make_uuid_key(&req.hisid);
    info!(
        "[{}] 请求连接设备 UUID {:08X}-{:04X}-{:04X}-{:04X}-{:04X}{:08X}",
        addr,
        req.hisid[0],
        req.hisid[1] >> 16,
        req.hisid[1] & 0xFFFF,
        req.hisid[2] >> 16,
        req.hisid[2] & 0xFFFF,
        req.hisid[3]
    );

    let device = {
        let reg = registry.read().await;
        reg.get(&target_key).cloned()
    };

    let device = match device {
        Some(d) => d,
        None => {
            warn!("[{}] 目标设备不存在", addr);
            let ack = build_ack_connect_error(&req.hisid, -1);
            let _ = tx.send(Message::Binary(ack.into()));
            return Ok(());
        }
    };

    // 验证密钥
    if device.mykey != req.hiskey {
        warn!("[{}] 密钥验证失败", addr);
        let ack = build_ack_connect_error(&req.hisid, -2);
        let _ = tx.send(Message::Binary(ack.into()));
        return Ok(());
    }
    if !device.alive {
        warn!("[{}] 目标设备不在线", addr);
        let ack = build_ack_connect_error(&req.hisid, -3);
        let _ = tx.send(Message::Binary(ack.into()));
        return Ok(());
    }
    if device.role != 1 {
        warn!("[{}] 目标设备角色不允许被连接", addr);
        let ack = build_ack_connect_error(&req.hisid, -4);
        let _ = tx.send(Message::Binary(ack.into()));
        return Ok(());
    }

    // 连接成功, 回复客户端
    let ack = build_ack_connect_success(&req.hisid, &client_uuid, &device.extradata0);
    let _ = tx.send(Message::Binary(ack.into()));

    // 通知设备端准备 Offer
    let notify = build_req_offer(
        &client_uuid,
        &stun_turn_info.strdatas,
        &stun_turn_info.strtypes,
        stun_turn_info.strcount,
        extra0,
    );
    let _ = device.sender.send(Message::Binary(notify.into()));

    Ok(())
}

/// 转发设备端的 SDP Offer 给客户端 (0x10006 -> 0x10007)
async fn handle_offer(
    data: &[u8],
    _conn_id: u64,
    my_id: &mut Option<[u32; 4]>,
    registry: &PeerRegistry,
    stun_turn_info: &StunTurnInfo,
    _tx: &mpsc::UnboundedSender<Message>,
    _addr: SocketAddr,
) -> Result<()> {
    let device_id = match my_id {
        Some(id) => *id,
        None => return Err(anyhow::anyhow!("设备未登录, 无法提交 Offer")),
    };

    let (client_id, sdplen, sdp) =
        parse_nti_offer(data).ok_or_else(|| anyhow::anyhow!("Offer 消息解析失败"))?;
    if sdplen == 0 || data.len() != OFFER_SIZE + sdplen as usize || sdp.is_empty() {
        return Err(anyhow::anyhow!("Offer SDP 长度异常"));
    }
    let sdp_str = std::str::from_utf8(sdp).map_err(|_| anyhow::anyhow!("SDP 不是有效的 UTF-8"))?;
    if sdp_str.len() < 64 || !is_valid_sdp(sdp_str) {
        return Err(anyhow::anyhow!("SDP 格式无效"));
    }

    let client_handle = {
        let reg = registry.read().await;
        reg.get(&make_uuid_key(&client_id)).cloned()
    };

    if let Some(client) = client_handle {
        if client.alive {
            let offer2 = build_offer2(
                &device_id,
                sdp,
                &stun_turn_info.strdatas,
                &stun_turn_info.strtypes,
                stun_turn_info.strcount,
            );
            let _ = client.sender.send(Message::Binary(offer2.into()));
        }
    }
    Ok(())
}

/// 转发客户端的 SDP Answer 给设备端 (0x10008 中继)
async fn handle_answer(
    data: &[u8],
    _conn_id: u64,
    my_id: &mut Option<[u32; 4]>,
    registry: &PeerRegistry,
    _tx: &mpsc::UnboundedSender<Message>,
    _addr: SocketAddr,
) -> Result<()> {
    let client_id = match my_id {
        Some(id) => *id,
        None => return Err(anyhow::anyhow!("客户端未连接, 无法提交 Answer")),
    };

    let (device_id, sdplen, sdp) =
        parse_nti_answer(data).ok_or_else(|| anyhow::anyhow!("Answer 消息解析失败"))?;
    if sdplen == 0 || data.len() != ANSWER_SIZE + sdplen as usize || sdp.is_empty() {
        return Err(anyhow::anyhow!("Answer SDP 长度异常"));
    }
    let sdp_str = std::str::from_utf8(sdp).map_err(|_| anyhow::anyhow!("SDP 不是有效的 UTF-8"))?;
    if sdp_str.len() < 64 || !is_valid_sdp(sdp_str) {
        return Err(anyhow::anyhow!("SDP 格式无效"));
    }

    let device_handle = {
        let reg = registry.read().await;
        reg.get(&make_uuid_key(&device_id)).cloned()
    };

    if let Some(device) = device_handle {
        if device.alive {
            let relay = build_relay_answer(&client_id, sdplen, sdp);
            let _ = device.sender.send(Message::Binary(relay.into()));
        }
    }
    Ok(())
}

/// 返回在线设备列表 (0x20001 -> 0x20002)
async fn handle_online(
    _conn_id: u64,
    my_id: &mut Option<[u32; 4]>,
    registry: &PeerRegistry,
    tx: &mpsc::UnboundedSender<Message>,
    _addr: SocketAddr,
) -> Result<()> {
    let self_id = my_id.unwrap_or([0u32; 4]);
    let reg = registry.read().await;
    let devices: Vec<[u32; 4]> = reg
        .iter()
        .filter(|(&id, h)| h.role == 1 && h.alive && id != self_id)
        .map(|(&id, _)| id)
        .collect();
    drop(reg);

    let ack = build_ack_online(&devices);
    let _ = tx.send(Message::Binary(ack.into()));
    Ok(())
}

/// 程序入口
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::Config::load(CONFIG_FILE);
    let port = if cfg.localport == 0 { 6688 } else { cfg.localport };
    let registry = new_registry();
    let stun_info = Arc::new(cfg.stun_turn_info);

    serve_ws(port, registry.clone(), stun_info.clone());

    if cfg.support_ssl {
        let ssl_cfg = cfg.ssl.as_ref().unwrap();
        let ssl_port = if ssl_cfg.localport == 0 { 6689 } else { ssl_cfg.localport };
        serve_wss(ssl_port, &ssl_cfg.pem_cert_file, &ssl_cfg.pem_key_file,
                  registry.clone(), stun_info.clone())?;
    }

    info!("信令服务器启动成功, WS 端口 {}, WSS 端口 {}", port, cfg.ssl.as_ref().map_or("未启用".to_string(), |s| s.localport.to_string()));
    info!("等待 Ctrl+C 关闭...");

    tokio::signal::ctrl_c().await?;
    info!("正在关闭...");
    Ok(())
}
