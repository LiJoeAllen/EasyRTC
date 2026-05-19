/// SDP (Session Description Protocol) 有效性验证
/// 用于验证 WebRTC 的 SDP Offer/Answer 是否格式正确

/// 验证 SDP 字符串是否包含必要字段
/// 检查项: v=0 版本号, o= 源信息, s= 会话名, t= 时间描述, m= 媒体描述
pub fn is_valid_sdp(sdp: &str) -> bool {
    if !sdp.starts_with("v=0") {
        return false;
    }
    if sdp.find("o=").is_none()
        || sdp.find("s=").is_none()
        || sdp.find("t=").is_none()
        || sdp.find("m=").is_none()
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_有效_sdp() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=Test\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\n";
        assert!(is_valid_sdp(sdp));
    }

    #[test]
    fn test_无效_sdp_缺版本号() {
        assert!(!is_valid_sdp("o=- 0 0 IN IP4 0.0.0.0\r\ns=Test\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\n"));
    }

    #[test]
    fn test_无效_sdp_缺媒体描述() {
        assert!(!is_valid_sdp("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=Test\r\nt=0 0\r\n"));
    }

    #[test]
    fn test_空字符串无效() {
        assert!(!is_valid_sdp(""));
    }

    #[test]
    fn test_真实_webrtc_sdp() {
        let sdp = "v=0\r\n\
            o=- 12345 67890 IN IP4 192.168.1.1\r\n\
            s=EasyRTC\r\n\
            t=0 0\r\n\
            a=group:BUNDLE audio video\r\n\
            m=audio 9 UDP/TLS/RTP/SAVPF 111 112\r\n\
            c=IN IP4 0.0.0.0\r\n\
            a=rtpmap:111 opus/48000/2\r\n\
            m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
            c=IN IP4 0.0.0.0\r\n\
            a=rtpmap:96 H264/90000\r\n";
        assert!(is_valid_sdp(sdp));
    }
}
