/// 信令服务器配置解析
/// 读取 signalserver.ini 配置文件, 解析服务器端口、STUN/TURN 服务器、SSL 证书等配置
/// 并构建用于转发给客户端的 STUN/TURN 信息二进制块 (STRDATAS_INFO 格式)

use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone)]
pub struct StunConfig {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct TurnConfig {
    pub url: String,
    pub username: String,
    pub credential: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SslConfig {
    pub localport: u16,
    pub pem_cert_file: String,
    pub pem_key_file: String,
    pub key_password: String,
}

#[derive(Debug, Clone)]
pub struct StunTurnInfo {
    pub strdatas: Vec<u8>,
    pub strtypes: [i8; 8],
    pub strcount: i8,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub localport: u16,
    pub stun_count: usize,
    pub turn_count: usize,
    pub support_ssl: bool,
    pub stun: Vec<StunConfig>,
    pub turn: Vec<TurnConfig>,
    pub ssl: Option<SslConfig>,
    pub stun_turn_info: StunTurnInfo,
}

fn trim_quotes(s: &str) -> String {
    s.trim_matches('"').trim().to_string()
}

fn parse_ini(path: &str) -> HashMap<String, HashMap<String, String>> {
    let content = fs::read_to_string(path).unwrap_or_default();
    let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current_section = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if let Some(end) = line.find(']') {
                current_section = line[1..end].to_string();
                result.entry(current_section.clone()).or_default();
            }
        } else if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value = line[eq_pos + 1..].trim().to_string();
            result
                .entry(current_section.clone())
                .or_default()
                .insert(key, value);
        }
    }
    result
}

fn get_int(map: &HashMap<String, String>, key: &str, default: u16) -> u16 {
    map.get(key)
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(default)
}

impl Config {
    pub fn load(path: &str) -> Self {
        let ini = parse_ini(path);

        let base = ini.get("base").cloned().unwrap_or_default();
        let localport = get_int(&base, "localport", 6688);
        let stun_count = get_int(&base, "stuncount", 0).min(2) as usize;
        let turn_count = get_int(&base, "turncount", 0).min(2) as usize;
        let support_ssl = get_int(&base, "supportssl", 0) == 1;

        let mut stun = Vec::with_capacity(stun_count);
        for i in 0..stun_count {
            let section = ini.get(&format!("stun{}", i));
            stun.push(StunConfig {
                url: section
                    .and_then(|s| s.get("url"))
                    .map(|v| trim_quotes(v))
                    .unwrap_or_default(),
            });
        }

        let mut turn = Vec::with_capacity(turn_count);
        for i in 0..turn_count {
            let section = ini.get(&format!("turn{}", i));
            turn.push(TurnConfig {
                url: section
                    .and_then(|s| s.get("url"))
                    .map(|v| trim_quotes(v))
                    .unwrap_or_default(),
                username: section
                    .and_then(|s| s.get("username"))
                    .map(|v| trim_quotes(v))
                    .unwrap_or_default(),
                credential: section
                    .and_then(|s| s.get("credential"))
                    .map(|v| trim_quotes(v))
                    .unwrap_or_default(),
            });
        }

        let ssl = if support_ssl {
            let ssl_sec = ini.get("ssl");
            ssl_sec.map(|s| SslConfig {
                localport: get_int(s, "localport", 6689),
                pem_cert_file: s
                    .get("pemcertfile")
                    .map(|v| trim_quotes(v))
                    .unwrap_or_default(),
                pem_key_file: s
                    .get("pemkeyfile")
                    .map(|v| trim_quotes(v))
                    .unwrap_or_default(),
                key_password: s
                    .get("keypassword")
                    .map(|v| trim_quotes(v))
                    .unwrap_or_default(),
            })
        } else {
            None
        };

        let mut info = StunTurnInfo {
            strdatas: vec![0u8; 2048],
            strtypes: [0i8; 8],
            strcount: 0,
        };

        let mut i_pos = 0usize;
        let strdatas_len = info.strdatas.len();

        for i in 0..stun_count.min(stun.len()) {
            let url_bytes = stun[i].url.as_bytes();
            let end = i_pos + url_bytes.len() + 1;
            if end > strdatas_len {
                break;
            }
            info.strtypes[info.strcount as usize] = 0x00;
            info.strdatas[i_pos..i_pos + url_bytes.len()].copy_from_slice(url_bytes);
            info.strdatas[i_pos + url_bytes.len()] = 0;
            i_pos = end;
            info.strcount += 1;
        }

        for i in 0..turn_count.min(turn.len()) {
            let url_bytes = turn[i].url.as_bytes();
            let end = i_pos + url_bytes.len() + 1;
            if end > strdatas_len {
                break;
            }
            info.strtypes[info.strcount as usize] = 0x04;
            info.strdatas[i_pos..i_pos + url_bytes.len()].copy_from_slice(url_bytes);
            info.strdatas[i_pos + url_bytes.len()] = 0;
            i_pos = end;
            info.strcount += 1;

            let user_bytes = turn[i].username.as_bytes();
            let end = i_pos + user_bytes.len() + 1;
            if end > strdatas_len {
                break;
            }
            info.strtypes[info.strcount as usize] = 0x02;
            info.strdatas[i_pos..i_pos + user_bytes.len()].copy_from_slice(user_bytes);
            info.strdatas[i_pos + user_bytes.len()] = 0;
            i_pos = end;
            info.strcount += 1;

            let cred_bytes = turn[i].credential.as_bytes();
            let end = i_pos + cred_bytes.len() + 1;
            if end > strdatas_len {
                break;
            }
            info.strtypes[info.strcount as usize] = 0x03;
            info.strdatas[i_pos..i_pos + cred_bytes.len()].copy_from_slice(cred_bytes);
            info.strdatas[i_pos + cred_bytes.len()] = 0;
            i_pos = end;
            info.strcount += 1;
        }

        info.strdatas.truncate(i_pos);

        Config {
            localport,
            stun_count,
            turn_count,
            support_ssl,
            stun,
            turn,
            ssl,
            stun_turn_info: info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_配置默认值() {
        // 不存在的配置文件应使用默认值
        let cfg = Config::load("_nonexistent_file_.ini");
        assert_eq!(cfg.localport, 6688);
        assert!(!cfg.support_ssl);
        assert!(cfg.ssl.is_none());
        assert_eq!(cfg.stun_count, 0);
        assert_eq!(cfg.turn_count, 0);
    }

    #[test]
    fn test_解析完整配置() {
        let ini_content = "[base]
localport = 19000
stuncount = 1
turncount = 1
supportssl = 0

[stun0]
url = \"stun.qq.com:3478\"

[turn0]
url = \"turn.example.com:443\"
username = \"user1\"
credential = \"pass1\"
";
        let mut tmp = std::env::temp_dir();
        tmp.push("test_signalserver_config.ini");
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(ini_content.as_bytes()).unwrap();

        let cfg = Config::load(tmp.to_str().unwrap());
        std::fs::remove_file(&tmp).ok();

        assert_eq!(cfg.localport, 19000);
        assert_eq!(cfg.stun_count, 1);
        assert_eq!(cfg.turn_count, 1);
        assert!(!cfg.support_ssl);
        assert_eq!(cfg.stun[0].url, "stun.qq.com:3478");
        assert_eq!(cfg.turn[0].url, "turn.example.com:443");
    }

    #[test]
    fn test_支持_ssl配置() {
        let ini_content = "[base]
localport = 6688
supportssl = 1
stuncount = 0
turncount = 0

[ssl]
localport = 6689
pemcertfile = \"cert.pem\"
pemkeyfile = \"key.pem\"
keypassword = \"\"
";
        let mut tmp = std::env::temp_dir();
        tmp.push("test_signalserver_ssl.ini");
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(ini_content.as_bytes()).unwrap();

        let cfg = Config::load(tmp.to_str().unwrap());
        std::fs::remove_file(&tmp).ok();

        assert!(cfg.support_ssl);
        let ssl = cfg.ssl.unwrap();
        assert_eq!(ssl.localport, 6689);
        assert_eq!(ssl.pem_cert_file, "cert.pem");
        assert_eq!(ssl.pem_key_file, "key.pem");
    }

    #[test]
    fn test_stun_turn_info_编码() {
        let ini_content = "[base]
localport = 6688
stuncount = 1
turncount = 1
supportssl = 0

[stun0]
url = \"stun.l.google.com:19302\"

[turn0]
url = \"turn.openrelayproject.org:443\"
username = \"myuser\"
credential = \"mypass\"
";
        let mut tmp = std::env::temp_dir();
        tmp.push("test_signalserver_stun_turn.ini");
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(ini_content.as_bytes()).unwrap();

        let cfg = Config::load(tmp.to_str().unwrap());
        std::fs::remove_file(&tmp).ok();

        let info = &cfg.stun_turn_info;
        assert_eq!(info.strcount, 4); // stun_url, turn_url, turn_user, turn_pass
        assert_eq!(info.strtypes[0], 0x00); // STUN 类型
        assert_eq!(info.strtypes[1], 0x04); // TURN URL 类型
        assert_eq!(info.strtypes[2], 0x02); // TURN 用户名
        assert_eq!(info.strtypes[3], 0x03); // TURN 密码

        // 验证 strdatas 包含所有字符串, 以 \0 分隔
        let datas = info.strdatas.as_slice();
        let stun_end = datas.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&datas[..stun_end], b"stun.l.google.com:19302");
    }
}
