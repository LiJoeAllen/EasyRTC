/// 二进制信令协议编解码
///
/// 实现 EasyRTC 自定义的 packed-binary 信令协议, 保持与 C 版本完全兼容:
/// - 所有多字节整数采用 Little-Endian 编码
/// - 消息头固定 8 字节 (length + msgtype)
/// - 协议结构使用 __attribute__((packed)) 布局

use std::io::{Cursor, Read};

// ==================== 消息类型常量 ====================
pub const MSG_REQ_LOGIN: u32 = 0x10001;       // 设备端 -> 服务器: 登录/注册
pub const MSG_ACK_LOGIN: u32 = 0x10002;       // 服务器 -> 设备端: 登录确认
pub const MSG_REQ_CONNECT: u32 = 0x10003;     // 客户端 -> 服务器: 请求连接设备
pub const MSG_ACK_CONNECT: u32 = 0x10004;     // 服务器 -> 客户端: 连接请求应答
pub const MSG_REQ_OFFER: u32 = 0x10005;       // 服务器 -> 设备端: 请求Offer
pub const MSG_NTI_OFFER: u32 = 0x10006;       // 设备端 -> 服务器: 提交SDP Offer
pub const MSG_NTI_OFFER2: u32 = 0x10007;      // 服务器 -> 客户端: 转发Offer+ICE配置
pub const MSG_NTI_ANSWER: u32 = 0x10008;      // 客户端 <-> 服务器 <-> 设备端: SDP Answer
pub const MSG_REQ_ONLINE: u32 = 0x20001;      // 客户端 -> 服务器: 请求在线设备列表
pub const MSG_ACK_ONLINE: u32 = 0x20002;      // 服务器 -> 客户端: 在线设备列表

// ==================== 消息固定部分大小 ====================
pub const REQ_LOGIN_SIZE: usize = 76;    // sizeof(REQ_LOGINUSER_INFO)
pub const ACK_LOGIN_SIZE: usize = 28;    // sizeof(ACK_LOGINUSER_INFO)
pub const REQ_CONNECT_SIZE: usize = 60;  // sizeof(REQ_CONNECTUSER_INFO)
pub const ACK_CONNECT_SIZE: usize = 46;  // sizeof(ACK_CONNECTUSER_INFO)
pub const OFFER_SIZE: usize = 26;        // sizeof(NTI_WEBRTCOFFER_INFO)
pub const OFFER2_SIZE: usize = 37;       // sizeof(NTI_WEBRTCOFFER_INFO2)
pub const ANSWER_SIZE: usize = 26;       // sizeof(NTI_WEBRTCANSWER_INFO)
pub const REQ_OFFER_SIZE: usize = 37;    // sizeof(REQ_GETWEBRTCOFFER_INFO)
pub const BASE_SIZE: usize = 8;          // sizeof(BASE_MSG_INFO)

// ==================== 内部辅助函数 ====================

fn read_u32(c: &mut Cursor<&[u8]>) -> u32 {
    let mut b = [0u8; 4];
    c.read_exact(&mut b).unwrap();
    u32::from_le_bytes(b)
}

fn read_u16(c: &mut Cursor<&[u8]>) -> u16 {
    let mut b = [0u8; 2];
    c.read_exact(&mut b).unwrap();
    u16::from_le_bytes(b)
}

// ==================== 基础消息头 ====================

#[derive(Debug)]
pub struct BaseHeader {
    pub length: u32,   // 消息总长度 (含头部)
    pub msgtype: u32,  // 消息类型
}

/// 解析基础消息头 (8 字节)
pub fn parse_base(data: &[u8]) -> Option<BaseHeader> {
    if data.len() < 8 {
        return None;
    }
    let mut c = Cursor::new(data);
    Some(BaseHeader {
        length: read_u32(&mut c),
        msgtype: read_u32(&mut c),
    })
}

// ==================== 登录协议 (0x10001/0x10002) ====================

#[derive(Debug)]
pub struct ReqLogin {
    pub myid: [u32; 4],     // 128位设备UUID
    pub mysn: [u32; 4],     // 128位序列号
    pub mykey: [u8; 32],    // 32字节认证密钥
    pub extradatalen0: u16, // 额外数据长度 (转发给另一端)
    pub extradatalen1: u16, // 额外数据长度 (给信令服务器)
}

/// 解析设备登录请求 (REQ_LOGINUSER_INFO)
pub fn parse_req_login(data: &[u8]) -> Option<(ReqLogin, &[u8], &[u8])> {
    if data.len() < REQ_LOGIN_SIZE {
        return None;
    }
    let mut c = Cursor::new(data);
    let _len = read_u32(&mut c);
    let mt = read_u32(&mut c);
    if mt != MSG_REQ_LOGIN {
        return None;
    }
    let mut myid = [0u32; 4];
    for v in &mut myid { *v = read_u32(&mut c); }
    let mut mysn = [0u32; 4];
    for v in &mut mysn { *v = read_u32(&mut c); }
    let mut mykey = [0u8; 32];
    c.read_exact(&mut mykey).unwrap();
    let extradatalen0 = read_u16(&mut c);
    let extradatalen1 = read_u16(&mut c);
    let extra0 = &data[REQ_LOGIN_SIZE..REQ_LOGIN_SIZE + extradatalen0 as usize];
    let extra1 = &data[REQ_LOGIN_SIZE + extradatalen0 as usize..];
    Some((ReqLogin { myid, mysn, mykey, extradatalen0, extradatalen1 }, extra0, extra1))
}

/// 构建登录确认消息 (ACK_LOGINUSER_INFO)
pub fn build_ack_login(myid: &[u32; 4]) -> Vec<u8> {
    let mut b = Vec::with_capacity(ACK_LOGIN_SIZE);
    b.extend_from_slice(&(ACK_LOGIN_SIZE as u32).to_le_bytes());
    b.extend_from_slice(&MSG_ACK_LOGIN.to_le_bytes());
    for v in myid { b.extend_from_slice(&v.to_le_bytes()); }
    b.extend_from_slice(&0i32.to_le_bytes()); // status = 0 (成功)
    b
}

// ==================== 连接请求协议 (0x10003/0x10004) ====================

#[derive(Debug)]
pub struct ReqConnect {
    pub hisid: [u32; 4],     // 目标设备UUID
    pub hiskey: [u8; 32],    // 目标设备认证密钥
    pub extradatalen0: u16,  // 额外数据长度 (转发给设备端)
    pub extradatalen1: u16,  // 额外数据长度 (给信令服务器)
}

/// 解析客户端连接请求 (REQ_CONNECTUSER_INFO)
pub fn parse_req_connect(data: &[u8]) -> Option<(ReqConnect, &[u8], &[u8])> {
    if data.len() < REQ_CONNECT_SIZE {
        return None;
    }
    let mut c = Cursor::new(data);
    let _len = read_u32(&mut c);
    let mt = read_u32(&mut c);
    if mt != MSG_REQ_CONNECT { return None; }
    let mut hisid = [0u32; 4];
    for v in &mut hisid { *v = read_u32(&mut c); }
    let mut hiskey = [0u8; 32];
    c.read_exact(&mut hiskey).unwrap();
    let extradatalen0 = read_u16(&mut c);
    let extradatalen1 = read_u16(&mut c);
    let extra0 = &data[REQ_CONNECT_SIZE..REQ_CONNECT_SIZE + extradatalen0 as usize];
    let extra1 = &data[REQ_CONNECT_SIZE + extradatalen0 as usize..];
    Some((ReqConnect { hisid, hiskey, extradatalen0, extradatalen1 }, extra0, extra1))
}

/// 构建连接请求错误应答 (status != 0)
pub fn build_ack_connect_error(hisid: &[u32; 4], status: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(ACK_CONNECT_SIZE);
    b.extend_from_slice(&(ACK_CONNECT_SIZE as u32).to_le_bytes());
    b.extend_from_slice(&MSG_ACK_CONNECT.to_le_bytes());
    for v in hisid { b.extend_from_slice(&v.to_le_bytes()); }
    for _ in 0..4 { b.extend_from_slice(&0u32.to_le_bytes()); }
    b.extend_from_slice(&status.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b
}

/// 构建连接请求成功应答 (status = 0, 包含设备额外数据)
pub fn build_ack_connect_success(
    hisid: &[u32; 4],
    myid: &[u32; 4],
    device_extra: &[u8],
) -> Vec<u8> {
    let size = ACK_CONNECT_SIZE + device_extra.len();
    let mut b = Vec::with_capacity(size);
    b.extend_from_slice(&(size as u32).to_le_bytes());
    b.extend_from_slice(&MSG_ACK_CONNECT.to_le_bytes());
    for v in hisid { b.extend_from_slice(&v.to_le_bytes()); }
    for v in myid { b.extend_from_slice(&v.to_le_bytes()); }
    b.extend_from_slice(&0i32.to_le_bytes());
    b.extend_from_slice(&(device_extra.len() as u16).to_le_bytes());
    b.extend_from_slice(device_extra);
    b
}

// ==================== Offer 请求协议 (0x10005) ====================

/// 构建获取Offer请求 (服务器 -> 设备端)
pub fn build_req_offer(
    client_id: &[u32; 4],
    strdatas: &[u8],
    strtypes: &[i8; 8],
    strcount: i8,
    extra: &[u8],
) -> Vec<u8> {
    let size = REQ_OFFER_SIZE + strdatas.len() + extra.len();
    let mut b = Vec::with_capacity(size);
    b.extend_from_slice(&(size as u32).to_le_bytes());
    b.extend_from_slice(&MSG_REQ_OFFER.to_le_bytes());
    for v in client_id { b.extend_from_slice(&v.to_le_bytes()); }
    b.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    b.extend_from_slice(&(strdatas.len() as u16).to_le_bytes());
    b.push(strcount as u8);
    for v in strtypes { b.push(*v as u8); }
    b.extend_from_slice(strdatas);
    b.extend_from_slice(extra);
    b
}

// ==================== Offer 转发协议 (0x10006/0x10007) ====================

/// 构建 Offer2 转发消息 (服务器 -> 客户端, 含ICE配置)
pub fn build_offer2(
    device_id: &[u32; 4],
    sdp: &[u8],
    strdatas: &[u8],
    strtypes: &[i8; 8],
    strcount: i8,
) -> Vec<u8> {
    let size = OFFER2_SIZE + strdatas.len() + sdp.len();
    let mut b = Vec::with_capacity(size);
    b.extend_from_slice(&(size as u32).to_le_bytes());
    b.extend_from_slice(&MSG_NTI_OFFER2.to_le_bytes());
    for v in device_id { b.extend_from_slice(&v.to_le_bytes()); }
    b.extend_from_slice(&(sdp.len() as u16).to_le_bytes());
    b.extend_from_slice(&(strdatas.len() as u16).to_le_bytes());
    b.push(strcount as u8);
    for v in strtypes { b.push(*v as u8); }
    b.extend_from_slice(strdatas);
    b.extend_from_slice(sdp);
    b
}

/// 解析设备端提交的 SDP Offer (NTI_WEBRTCOFFER_INFO)
pub fn parse_nti_offer(data: &[u8]) -> Option<([u32; 4], u16, &[u8])> {
    if data.len() <= OFFER_SIZE { return None; }
    let mut c = Cursor::new(data);
    let _len = read_u32(&mut c);
    let mt = read_u32(&mut c);
    if mt != MSG_NTI_OFFER { return None; }
    let mut hisid = [0u32; 4];
    for v in &mut hisid { *v = read_u32(&mut c); }
    let sdplen = read_u16(&mut c) as usize;
    let sdp = &data[OFFER_SIZE..OFFER_SIZE + sdplen];
    Some((hisid, sdplen as u16, sdp))
}

// ==================== Answer 中继协议 (0x10008) ====================

/// 解析客户端提交的 SDP Answer (NTI_WEBRTCANSWER_INFO)
pub fn parse_nti_answer(data: &[u8]) -> Option<([u32; 4], u16, &[u8])> {
    if data.len() <= ANSWER_SIZE { return None; }
    let mut c = Cursor::new(data);
    let _len = read_u32(&mut c);
    let mt = read_u32(&mut c);
    if mt != MSG_NTI_ANSWER { return None; }
    let mut hisid = [0u32; 4];
    for v in &mut hisid { *v = read_u32(&mut c); }
    let sdplen = read_u16(&mut c) as usize;
    let sdp = &data[ANSWER_SIZE..ANSWER_SIZE + sdplen];
    Some((hisid, sdplen as u16, sdp))
}

/// 构建 Answer 中继消息 (服务器 -> 设备端, 替换 hisid 为客户端UUID)
pub fn build_relay_answer(hisid: &[u32; 4], sdplen: u16, sdp: &[u8]) -> Vec<u8> {
    let size = ANSWER_SIZE + sdplen as usize;
    let mut b = Vec::with_capacity(size + 1);
    b.extend_from_slice(&(size as u32).to_le_bytes());
    b.extend_from_slice(&MSG_NTI_ANSWER.to_le_bytes());
    for v in hisid { b.extend_from_slice(&v.to_le_bytes()); }
    b.extend_from_slice(&sdplen.to_le_bytes());
    b.extend_from_slice(sdp);
    b
}

// ==================== 在线设备列表协议 (0x20001/0x20002) ====================

/// 构建在线设备列表应答
pub fn build_ack_online(devices: &[[u32; 4]]) -> Vec<u8> {
    let count = devices.len();
    let size = BASE_SIZE + 4 + count * 16;
    let mut b = Vec::with_capacity(size);
    b.extend_from_slice(&(size as u32).to_le_bytes());
    b.extend_from_slice(&MSG_ACK_ONLINE.to_le_bytes());
    b.extend_from_slice(&(count as u32).to_le_bytes());
    for dev in devices {
        for v in dev { b.extend_from_slice(&v.to_le_bytes()); }
    }
    b
}

// ==================== 测试用例 ====================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- 消息常量验证 ----------
    #[test]
    fn test_消息大小常量正确() {
        assert_eq!(BASE_SIZE, 8);
        assert_eq!(REQ_LOGIN_SIZE, 76);
        assert_eq!(ACK_LOGIN_SIZE, 28);
        assert_eq!(REQ_CONNECT_SIZE, 60); // sizeof(REQ_CONNECTUSER_INFO): 4+4+16+32+2+2
        assert_eq!(ACK_CONNECT_SIZE, 46);
        assert_eq!(OFFER_SIZE, 26);
        assert_eq!(OFFER2_SIZE, 37);
        assert_eq!(ANSWER_SIZE, 26);
        assert_eq!(REQ_OFFER_SIZE, 37);
    }

    // ---------- 基础消息头 ----------
    #[test]
    fn test_parse_base_正常() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&(100u32.to_le_bytes()));
        data[4..8].copy_from_slice(&MSG_REQ_LOGIN.to_le_bytes());
        let h = parse_base(&data).unwrap();
        assert_eq!(h.length, 100);
        assert_eq!(h.msgtype, MSG_REQ_LOGIN);
    }

    #[test]
    fn test_parse_base_数据不足() {
        assert!(parse_base(&[0u8; 4]).is_none());
        assert!(parse_base(&[0u8; 7]).is_none());
    }

    // ---------- 登录协议 ----------
    #[test]
    fn test_parse_req_login_正常() {
        let myid: [u32; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        let mysn: [u32; 4] = [0x55555555, 0x66666666, 0x77777777, 0x88888888];
        let mykey = [0xABu8; 32];

        let mut data = Vec::new();
        data.extend_from_slice(&(REQ_LOGIN_SIZE as u32).to_le_bytes());
        data.extend_from_slice(&MSG_REQ_LOGIN.to_le_bytes());
        for v in &myid { data.extend_from_slice(&v.to_le_bytes()); }
        for v in &mysn { data.extend_from_slice(&v.to_le_bytes()); }
        data.extend_from_slice(&mykey);
        data.extend_from_slice(&0u16.to_le_bytes()); // extradatalen0
        data.extend_from_slice(&0u16.to_le_bytes()); // extradatalen1

        let (req, extra0, extra1) = parse_req_login(&data).unwrap();
        assert_eq!(req.myid, myid);
        assert_eq!(req.mysn, mysn);
        assert_eq!(req.mykey, mykey);
        assert!(extra0.is_empty());
        assert!(extra1.is_empty());
    }

    #[test]
    fn test_parse_req_login_带额外数据() {
        let mut data = vec![0u8; REQ_LOGIN_SIZE + 10];
        let extra_content = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let total_len = REQ_LOGIN_SIZE + extra_content.len();

        // 填充头部
        data[0..4].copy_from_slice(&(total_len as u32).to_le_bytes());
        data[4..8].copy_from_slice(&MSG_REQ_LOGIN.to_le_bytes());
        // myid = 0
        // mykey = 0
        // extradatalen0 = 10
        data[72..74].copy_from_slice(&(10u16).to_le_bytes());
        data[74..76].copy_from_slice(&(0u16).to_le_bytes()); // extradatalen1 = 0
        // extra0
        data[REQ_LOGIN_SIZE..total_len].copy_from_slice(&extra_content);

        let (req, extra0, extra1) = parse_req_login(&data).unwrap();
        assert_eq!(req.extradatalen0, 10);
        assert_eq!(extra0, &extra_content);
        assert!(extra1.is_empty());
    }

    #[test]
    fn test_parse_req_login_数据不足() {
        assert!(parse_req_login(&[0u8; REQ_LOGIN_SIZE - 1]).is_none());
    }

    #[test]
    fn test_build_ack_login() {
        let myid = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        let data = build_ack_login(&myid);
        assert_eq!(data.len(), ACK_LOGIN_SIZE);

        let h = parse_base(&data).unwrap();
        assert_eq!(h.length, ACK_LOGIN_SIZE as u32);
        assert_eq!(h.msgtype, MSG_ACK_LOGIN);
    }

    // ---------- 连接请求协议 ----------
    #[test]
    fn test_parse_req_connect_正常() {
        let hisid: [u32; 4] = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD];
        let hiskey = [0xCDu8; 32];

        let mut data = Vec::new();
        data.extend_from_slice(&(REQ_CONNECT_SIZE as u32).to_le_bytes());
        data.extend_from_slice(&MSG_REQ_CONNECT.to_le_bytes());
        for v in &hisid { data.extend_from_slice(&v.to_le_bytes()); }
        data.extend_from_slice(&hiskey);
        data.extend_from_slice(&0u16.to_le_bytes()); // extradatalen0
        data.extend_from_slice(&0u16.to_le_bytes()); // extradatalen1

        let (req, extra0, extra1) = parse_req_connect(&data).unwrap();
        assert_eq!(req.hisid, hisid);
        assert_eq!(req.hiskey, hiskey);
        assert!(extra0.is_empty());
        assert!(extra1.is_empty());
    }

    #[test]
    fn test_build_ack_connect_error() {
        let hisid = [1u32, 2, 3, 4];
        let data = build_ack_connect_error(&hisid, -1);
        let h = parse_base(&data).unwrap();
        assert_eq!(h.length, ACK_CONNECT_SIZE as u32);
        assert_eq!(h.msgtype, MSG_ACK_CONNECT);
    }

    #[test]
    fn test_build_ack_connect_error_编码() {
        let hisid: [u32; 4] = [0xDEAD, 0xBEEF, 0xCAFE, 0xBABE];
        let status = -2;
        let data = build_ack_connect_error(&hisid, status);

        // 验证第 41-44 字节为 status (little-endian)
        // 布局: length(4) + msgtype(4) + hisid(16) + myid(16) = offset 40
        let mut status_bytes = [0u8; 4];
        status_bytes.copy_from_slice(&data[40..44]);
        assert_eq!(i32::from_le_bytes(status_bytes), status);
    }

    #[test]
    fn test_build_ack_connect_success() {
        let hisid = [1u32, 2, 3, 4];
        let myid = [5u32, 6, 7, 8];
        let extra = vec![0xAA, 0xBB, 0xCC];
        let data = build_ack_connect_success(&hisid, &myid, &extra);
        assert_eq!(data.len(), ACK_CONNECT_SIZE + 3);

        let h = parse_base(&data).unwrap();
        assert_eq!(h.length, (ACK_CONNECT_SIZE + 3) as u32);
        assert_eq!(h.msgtype, MSG_ACK_CONNECT);

        // 验证 extra 数据在末尾
        assert_eq!(&data[data.len() - 3..], &extra[..]);
    }

    // ---------- Offer 协议 ----------
    #[test]
    fn test_build_parse_nti_offer_往返() {
        let hisid: [u32; 4] = [0x1234, 0x5678, 0x9ABC, 0xDEF0];
        let sdp = b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=Test\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\n";

        let mut data = Vec::new();
        let total_len = OFFER_SIZE + sdp.len();
        data.extend_from_slice(&(total_len as u32).to_le_bytes());
        data.extend_from_slice(&MSG_NTI_OFFER.to_le_bytes());
        for v in &hisid { data.extend_from_slice(&v.to_le_bytes()); }
        data.extend_from_slice(&(sdp.len() as u16).to_le_bytes());
        data.extend_from_slice(sdp);

        let (parsed_hisid, parsed_sdplen, parsed_sdp) = parse_nti_offer(&data).unwrap();
        assert_eq!(parsed_hisid, hisid);
        assert_eq!(parsed_sdplen as usize, sdp.len());
        assert_eq!(parsed_sdp, sdp);
    }

    #[test]
    fn test_parse_nti_offer_数据不足() {
        assert!(parse_nti_offer(&[0u8; OFFER_SIZE]).is_none());
    }

    #[test]
    fn test_parse_nti_offer_错误消息类型() {
        let mut data = vec![0u8; OFFER_SIZE + 1];
        data[4..8].copy_from_slice(&MSG_NTI_ANSWER.to_le_bytes()); // 故意用错误类型
        assert!(parse_nti_offer(&data).is_none());
    }

    #[test]
    fn test_build_offer2_长度正确() {
        let device_id = [1, 2, 3, 4];
        let sdp = b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=Test\r\nt=0 0\r\nm=audio 9 ...\r\n";
        let strdatas = b"stun.example.com\0turn.example.com\0user\0pass\0";
        let strtypes = [0x00, 0x04, 0x02, 0x03, 0, 0, 0, 0];
        let strcount = 4;

        let data = build_offer2(&device_id, sdp, strdatas, &strtypes, strcount);
        let expected = OFFER2_SIZE + strdatas.len() + sdp.len();
        assert_eq!(data.len(), expected);

        let h = parse_base(&data).unwrap();
        assert_eq!(h.length, expected as u32);
        assert_eq!(h.msgtype, MSG_NTI_OFFER2);
    }

    // ---------- Answer 协议 ----------
    #[test]
    fn test_build_parse_nti_answer_往返() {
        let hisid: [u32; 4] = [0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD];
        let sdp = b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=Answer\r\nt=0 0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n";

        // 构造原始消息
        let total_len = ANSWER_SIZE + sdp.len();
        let mut raw = Vec::new();
        raw.extend_from_slice(&(total_len as u32).to_le_bytes());
        raw.extend_from_slice(&MSG_NTI_ANSWER.to_le_bytes());
        for v in &hisid { raw.extend_from_slice(&v.to_le_bytes()); }
        raw.extend_from_slice(&(sdp.len() as u16).to_le_bytes());
        raw.extend_from_slice(sdp);

        let (parsed_id, parsed_len, parsed_sdp) = parse_nti_answer(&raw).unwrap();
        assert_eq!(parsed_id, hisid);
        assert_eq!(parsed_len as usize, sdp.len());
        assert_eq!(parsed_sdp, sdp);

        // 验证 build_relay_answer 使用新 hisid
        let new_hisid: [u32; 4] = [0x1111, 0x2222, 0x3333, 0x4444];
        let relay = build_relay_answer(&new_hisid, parsed_len, parsed_sdp);
        assert_eq!(relay.len(), ANSWER_SIZE + sdp.len());
        let (relay_id, _, _) = parse_nti_answer(&relay).unwrap();
        assert_eq!(relay_id, new_hisid);
    }

    // ---------- 在线设备列表 ----------
    #[test]
    fn test_build_ack_online_空列表() {
        let data = build_ack_online(&[]);
        let h = parse_base(&data).unwrap();
        assert_eq!(h.msgtype, MSG_ACK_ONLINE);

        // 验证 idscount = 0
        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(&data[8..12]);
        assert_eq!(u32::from_le_bytes(count_bytes), 0);
    }

    #[test]
    fn test_build_ack_online_多个设备() {
        let devices = vec![[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];
        let data = build_ack_online(&devices);
        assert_eq!(data.len(), BASE_SIZE + 4 + 3 * 16);

        // 验证数量
        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(&data[8..12]);
        assert_eq!(u32::from_le_bytes(count_bytes), 3);

        // 验证第一个设备UUID
        let mut first = [0u32; 4];
        for i in 0..4 {
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[12 + i * 4..16 + i * 4]);
            first[i] = u32::from_le_bytes(b);
        }
        assert_eq!(first, devices[0]);
    }

    #[test]
    fn test_各消息大小正确性() {
        // 验证所有消息固定部分大小 (与C __attribute__((packed)) 一致)
        // ACK_LOGINUSER_INFO: 4+4+16+4 = 28
        assert_eq!(ACK_LOGIN_SIZE, 28);

        // REQ_LOGINUSER_INFO: 4+4+16+16+32+2+2 = 76
        assert_eq!(REQ_LOGIN_SIZE, 76);

        // REQ_CONNECTUSER_INFO: 4+4+16+32+2+2 = 60
        assert_eq!(REQ_CONNECT_SIZE, 60);

        // ACK_CONNECTUSER_INFO: 4+4+16+16+4+2 = 46
        assert_eq!(ACK_CONNECT_SIZE, 46);

        // NTI_WEBRTCOFFER_INFO: 4+4+16+2 = 26
        assert_eq!(OFFER_SIZE, 26);

        // NTI_WEBRTCOFFER_INFO2: 4+4+16+2+2+1+8 = 37
        assert_eq!(OFFER2_SIZE, 37);

        // NTI_WEBRTCANSWER_INFO: 4+4+16+2 = 26
        assert_eq!(ANSWER_SIZE, 26);

        // REQ_GETWEBRTCOFFER_INFO: 4+4+16+2+2+1+8 = 37
        assert_eq!(REQ_OFFER_SIZE, 37);
    }
}
