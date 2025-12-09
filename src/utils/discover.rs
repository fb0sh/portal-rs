use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::{net::UdpSocket, time::timeout};

use crate::utils::{NetworkInfo, PortalCrypto, get_network_info};
pub async fn discover() -> Result<()> {
    // 绑定到指定网卡IP和端口
    let local_ip = Ipv4Addr::new(0, 0, 0, 0);
    let socket = UdpSocket::bind((local_ip, 25565)).await?;
    socket.set_broadcast(true)?;
    println!("Listening on {}:25565", local_ip);

    let mut buf = vec![0u8; 1024];

    loop {
        // 使用 Tokio 的 timeout 包裹 recv_from
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                println!("Received {} bytes from {}", len, src);
                let msg = &buf[..len];

                // 这里假设 PortalCrypto 是你自定义的加密/解析模块
                let pc = PortalCrypto::new("test_1213", "pass123");
                match pc.check_valid(msg)? {
                    true => {
                        let data: Vec<NetworkInfo> = pc.parse_portal_message(msg)?;
                        dbg!(data);
                    }
                    false => println!("Message is invalid"),
                }
            }
            Ok(Err(e)) => eprintln!("recv error: {}", e),
            Err(_) => {
                // 超时，继续循环
                eprintln!("timeout waiting for packet");
            }
        }
    }
}

pub async fn broadcast() -> Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::new(192, 168, 17, 66), 0)).await?;
    socket.set_broadcast(true)?;

    let broadcast_addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 31, 255), 25565);

    let n = get_network_info()?;
    let pc = PortalCrypto::new("test_1213", "pass123");
    let msg = pc.build_portal_message(&n)?;
    let msg_hash = Sha256::digest(&msg);
    println!("msg_hash: {:?}", msg_hash);
    socket.send_to(&msg, broadcast_addr).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_discover() {
        discover().await.unwrap();
    }

    #[tokio::test]
    async fn test_broadcast() {
        broadcast().await.unwrap();
    }

    #[tokio::test]
    async fn test_trans_info() {
        let n = get_network_info().unwrap();
        let pc = PortalCrypto::new("test_1213", "pass123");
        let msg = pc.build_portal_message(&n).unwrap();

        let pc2 = PortalCrypto::new("test_1213", "pass123");
        pc2.check_valid(&msg).unwrap();
        let data: Vec<NetworkInfo> = pc2.parse_portal_message(&msg).unwrap();
        dbg!(data);
    }
}
