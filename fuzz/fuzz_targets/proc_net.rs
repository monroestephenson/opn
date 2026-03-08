#![no_main]

use libfuzzer_sys::fuzz_target;

mod model {
    #[derive(Debug, Clone, PartialEq)]
    pub enum Protocol {
        Tcp,
        Udp,
    }
}

#[path = "../../src/net.rs"]
mod net;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);

    let _ = net::parse_proc_net_tcp(&input);
    let _ = net::parse_proc_net_tcp6(&input);
    let _ = net::parse_proc_net_udp(&input);
    let _ = net::parse_proc_net_udp6(&input);

    for line in input.lines() {
        let _ = net::parse_proc_net_tcp_line(line);
        let _ = net::parse_proc_net_tcp6_line(line);
        let _ = net::parse_proc_net_udp_line(line);
        let _ = net::parse_proc_net_udp6_line(line);
    }
});
