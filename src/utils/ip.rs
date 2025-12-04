use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use get_if_addrs::{IfAddr, Interface, get_if_addrs};

#[derive(Debug)]
pub struct NetworkInfo {
    pub name: String,
    pub ip: IpAddr,
    pub prefix: u8,
    pub broadcast: Option<IpAddr>,
    pub netmask: Option<Ipv4Addr>,
}

impl NetworkInfo {
    pub fn get_ipv4_addr_list(&self) -> Option<Vec<Ipv4Addr>> {
        match self.ip {
            IpAddr::V4(ip) => {
                if let (Some(netmask), Some(IpAddr::V4(broadcast))) = (self.netmask, self.broadcast)
                {
                    let network_u32 = u32::from(ip) & u32::from(netmask);
                    let broadcast_u32 = u32::from(broadcast);

                    let mut result = Vec::new();
                    for n in (network_u32 + 1)..broadcast_u32 {
                        result.push(Ipv4Addr::from(n));
                    }
                    Some(result)
                } else {
                    None
                }
            }
            IpAddr::V6(_) => None, // IPv6 不生成列表
        }
    }

    pub fn get_cidr(&self) -> String {
        format!("{}/{}", self.ip, self.prefix)
    }
}
pub fn get_network_info() -> Result<Vec<NetworkInfo>> {
    let mut network_info_list = Vec::new();

    let if_addrs = get_if_addrs()?
        .into_iter()
        .filter(|i| !i.is_loopback()) // 保留非 lo
        .collect::<Vec<Interface>>();

    for iface in if_addrs {
        match iface.addr {
            IfAddr::V4(v4) => {
                let ip = IpAddr::V4(v4.ip);
                let netmask = v4.netmask;
                let broadcast = Some(IpAddr::V4(v4.broadcast.unwrap_or(v4.ip)));
                let prefix = u32::from(netmask).count_ones() as u8;

                network_info_list.push(NetworkInfo {
                    name: iface.name,
                    ip,
                    prefix,
                    broadcast,
                    netmask: Some(netmask),
                });
            }
            IfAddr::V6(v6) => {
                let ip = IpAddr::V6(v6.ip);
                let prefix = 64_u8; // IPv6 默认前缀长度为 64

                network_info_list.push(NetworkInfo {
                    name: iface.name,
                    ip,
                    prefix,
                    broadcast: None,
                    netmask: None,
                });
            }
        }
    }

    Ok(network_info_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_get_network_info() {
        let networks = get_network_info().unwrap();

        assert!(!networks.is_empty(), "本机至少应该有一个非回环网卡");

        for net in &networks {
            println!("Name: {}", net.name);
            println!("CIDR: {}", net.get_cidr());
            println!("Broadcast: {:?}", net.broadcast);

            match net.ip {
                IpAddr::V4(_) => {
                    // 解包 Option
                    if let Some(ip_list) = net.get_ipv4_addr_list() {
                        println!("IPv4 可用 IP 数量: {}", ip_list.len());
                        println!(
                            "IPv4 列表前10个: {:?}",
                            &ip_list.iter().take(10).collect::<Vec<_>>()
                        );

                        // 简单检查：列表里的 IP 是合法的 IPv4
                        if let Some(first_ip) = ip_list.first() {
                            assert!(matches!(first_ip, &Ipv4Addr { .. }));
                        }
                    } else {
                        println!("IPv4 可用 IP 列表为空");
                    }
                }
                IpAddr::V6(_) => {
                    println!("IPv6 不生成 IP 列表");
                }
            }

            println!("-----------------------------");
        }
    }
}
