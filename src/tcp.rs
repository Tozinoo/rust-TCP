use std::io;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

impl Default for State {
    fn default () -> Self {
        //State::Closed
        State::Listen
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        nic : &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        match *self {
            State::Closed => {
                return;
            }
            State::Listen => {
                if !tcph.syn() {
                    // only expected SYN packet
                    return;
                }
                // need to start establishing a connection
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcph.destination_port(),
                    tcph.source_port(),
                    0,
                    0
                    // tcph.sequence_number(),
                    // tcph.window_size()
                );
                syn_ack.syn = true;
                syn_ack.syn = true;
                let mut ip = etherparse::Ipv4Header::new(
                    syn_ack.slice().len(),
                    64,
                    etherparse::IpTrafficClass::TCP,
                    iph.destination(),
                    iph.source()
                ).expect("asdf");

                // write out the headers
                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    ip.write(unwritten);
                    syn_ack.write(unwritten);
                    unwritten.len()
                };

                nic.send(&buf[..unwritten])
            }
            _ => {}
        }

    }
}