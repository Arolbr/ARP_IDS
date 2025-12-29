// 底层网络数据包捕获与解析库
use pnet::datalink::{self, Channel, DataLinkReceiver, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::util::MacAddr;

// IP 网段处理（用于推测网关）
use ipnetwork::IpNetwork;

// 获取本机 IP
use local_ip_address::local_ip;

// 标准库
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

// 以太网头长度（固定 14 字节）
const ETHERNET_HEADER_LEN: usize = 14;

// ARP 报文长度（固定 28 字节）
const ARP_PACKET_LEN: usize = 28;

// 最小 ARP 以太网帧长度
const MIN_BUFFER_SIZE: usize = ETHERNET_HEADER_LEN + ARP_PACKET_LEN;

// ARP 表：IP → MAC
type ArpTable = HashMap<Ipv4Addr, MacAddr>;

/// 列出所有网络接口，让用户选择监听哪个
fn select_interface() -> NetworkInterface {
    let interfaces = datalink::interfaces();

    // 打印接口信息
    for (i, iface) in interfaces.iter().enumerate() {
        println!(
            "[{}] {}  MAC: {:?}  IPs: {:?}",
            i, iface.name, iface.mac, iface.ips
        );
    }

    // 读取用户输入
    print!("\n请选择要监听的接口编号: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let idx: usize = input.trim().parse().unwrap_or(0);

    // 返回选中的接口
    interfaces.get(idx).expect("接口编号无效").clone()
}

/// 根据接口的 IPv4 网段推测网关 IP（通常为 *.1）
fn guess_gateway(interface: &NetworkInterface) -> Ipv4Addr {
    // 找到 IPv4 网段
    let subnet = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .expect("未找到 IPv4 网段");

    let cidr_v4 = match subnet.ip() {
        IpAddr::V4(ip) => ip,
        _ => panic!("仅支持 IPv4"),
    };

    // 获取 CIDR 前缀
    let prefix = match subnet {
        IpNetwork::V4(net) => net.prefix(),
        _ => 24,
    };

    // 计算网络地址
    let mask = (0xFFFFFFFFu32) << (32 - prefix);
    let base = u32::from(cidr_v4) & mask;

    // 默认认为网关是 .1
    Ipv4Addr::from(base + 1)
}

/// 被动监听 ARP Reply，检测 ARP 欺骗行为
fn arp_monitor(
    rx_mutex: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
    running: Arc<AtomicBool>,
    gateway_ip: Ipv4Addr,
) {
    // 记录 IP → MAC 的历史映射
    let mut arp_table: ArpTable = HashMap::new();

    // 用于限制网关告警刷屏
    let mut last_alert = Instant::now();

    println!("\n[监听] ARP 攻击检测已启动…\n");

    // 主监听循环
    while running.load(Ordering::SeqCst) {

        // 独占接收通道
        let mut rx = rx_mutex.lock().unwrap();

        // 获取一帧数据
        if let Ok(frame) = rx.next() {

            // 长度校验
            if frame.len() < MIN_BUFFER_SIZE {
                continue;
            }

            // 解析以太网帧
            let eth = match EthernetPacket::new(frame) {
                Some(e) => e,
                None => continue,
            };

            // 只处理 ARP
            if eth.get_ethertype() != EtherTypes::Arp {
                continue;
            }

            // 解析 ARP 报文
            let arp = match ArpPacket::new(&frame[ETHERNET_HEADER_LEN..]) {
                Some(a) => a,
                None => continue,
            };

            // 只关注 ARP Reply（欺骗最常见）
            if arp.get_operation() != ArpOperations::Reply {
                continue;
            }

            // ARP 报文中的 sender 信息
            let sender_ip = arp.get_sender_proto_addr();
            let sender_mac = arp.get_sender_hw_addr();

            // 以太网头中的源 MAC
            let eth_src_mac = eth.get_source();

            // 检测规则
            // ARP MAC ≠ Ethernet MAC
            if sender_mac != eth_src_mac {
                println!(
                    "ARP 欺骗告警（MAC 不一致）\n\
                     ▸ 攻击者 IP : {}\n\
                     ▸ 攻击者 MAC: {}\n\
                     ▸ 以太网源 MAC: {}\n",
                    sender_ip, sender_mac, eth_src_mac
                );
            }

            // 检测规则
            // IP → MAC 映射发生变化
            if let Some(old_mac) = arp_table.get(&sender_ip) {
                if *old_mac != sender_mac {

                    // 被冒充的一方
                    let victim_ip = sender_ip;
                    let victim_mac = old_mac;

                    println!(
                        "ARP 攻击检测到！\n\
                         ▸ 被冒充 IP（受害者 IP） : {}\n\
                         ▸ 受害者 MAC             : {}\n\
                         ▸ 攻击者 IP             : {}\n\
                         ▸ 攻击者 MAC            : {}\n",
                        victim_ip, victim_mac, sender_ip, sender_mac
                    );
                }
            } else {
                // 首次记录
                arp_table.insert(sender_ip, sender_mac);
            }

            // 检测规则
            // 网关 ARP 被劫持
            if sender_ip == gateway_ip {
                if let Some(old_mac) = arp_table.get(&gateway_ip) {
                    if *old_mac != sender_mac
                        && last_alert.elapsed() > Duration::from_secs(2)
                    {
                        println!(
                            "网关 ARP 被劫持！\n\
                             ▸ 网关 IP      : {}\n\
                             ▸ 原网关 MAC   : {}\n\
                             ▸ 伪造者 MAC   : {}\n",
                            gateway_ip, old_mac, sender_mac
                        );
                        last_alert = Instant::now();
                    }
                }
            }
        }
    }
}

// 主函数
fn main() {
    println!("=== ARP IDS ===");

    // 选择网卡
    let interface = select_interface();

    // 获取本机 IPv4
    let my_ip = match local_ip().unwrap() {
        IpAddr::V4(ip) => ip,
        _ => panic!("未检测到 IPv4"),
    };

    println!(
        "\n使用接口: {}  MAC: {:?}  本机 IP: {}\n",
        interface.name, interface.mac, my_ip
    );

    // 推测网关
    let gateway_ip = guess_gateway(&interface);
    println!("推测网关 IP: {}\n", gateway_ip);

    // 打开数据链路通道（只用 RX）
    let (_, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(_, rx)) => ((), rx),
        Ok(_) => panic!("不支持的通道类型"),
        Err(e) => panic!("打开通道失败: {}", e),
    };

    let rx_main = Arc::new(Mutex::new(rx));
    let running = Arc::new(AtomicBool::new(true));

    // 启动监听线程
    let r = running.clone();
    let rx_for_monitor = rx_main.clone();
    thread::spawn(move || {
        arp_monitor(rx_for_monitor, r, gateway_ip);
    });

    // Ctrl+C 优雅退出
    ctrlc::set_handler({
        let r = running.clone();
        move || {
            println!("\n[退出] 停止监听，程序结束。");
            r.store(false, Ordering::SeqCst);
        }
    })
    .unwrap();

    // 主线程阻塞
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }
}
