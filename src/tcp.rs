use std::io;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    //  Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

/**
    State of Send Sequence Space (RFC 793 S3.2 F4)

```
            1         2          3          4
       ----------|----------|----------|----------
              SND.UNA    SND.NXT    SND.UNA
                                   +SND.WND

 1 - old sequence numbers which have been acknowledged
 2 - sequence numbers of unacknowledged data
 3 - sequence numbers allowed for new data transmission
 4 - future sequence numbers which are not yet allowed
```
 */

struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

/**
    State of Receive Sequence Space (RFC 793 S3.2 F5)
```
                 1          2          3
           ----------|----------|----------
                  RCV.NXT    RCV.NXT
                            +RCV.WND

1 - old sequence numbers which have been acknowledged
2 - sequence numbers allowed for new reception
3 - future sequence numbers which are not yet allowed
```
 */

struct RecvSequenceSpace {
    ///  receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        let mut c = Connection {
            state : State::SynRcvd,
            send : SendSequenceSpace {
               iss,
               una : iss,
               nxt : iss + 1,
               wnd : 10,
                up : false,

                wl1: 0,
                wl2: 0,
            },
            recv : RecvSequenceSpace {
                irs : tcph.sequence_number(),
                nxt : tcph.sequence_number() + 1,
                wnd : tcph.window_size(),
                up : false,
            }
        };
        // keep track of sender info


        // decide on stuff we're sending them

        // need to start establishing a connection
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );


        syn_ack.acknowledgment_number = c.recv.nxt + 1;
        syn_ack.syn = true;
        syn_ack.syn = true;

        let mut ip = etherparse::Ipv4Header::new(
            syn_ack.header_len() as u16,
            64,
            etherparse::IpNumber::TCP,
            [
                iph.destination()[0],
                iph.destination()[1],
                iph.destination()[2],
                iph.destination()[3],
            ],
            [
                iph.source()[0],
                iph.source()[1],
                iph.source()[2],
                iph.source()[3],
            ],
        )
        .expect("asdf");
        // kernel is nice and does this for us
        // syn_ack.checksum = syn_ack.calc_checksum_ipv4(&ip, &[]).expect("failed to compute checksum");

        // write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            ip.write(&mut unwritten);
            syn_ack.write(&mut unwritten);
            unwritten.len()
        };

        nic.send(&buf[..unwritten])?;
        Ok(Some(c))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        Ok(())
    }
}
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// [45,
// 00,
// 00, 3c,
// 05, 3e,
// 40, 00,
// 40,
// 06,
// b4, 2a,
// c0, a8, 00, 01,
// c0, a8, 00, 02]
//
// [45,
// 00,
// 00, 28,
// 00, 00,
// 40, 00,
// 40,
// 06,
// b9, 7c,
// c0, a8, 00, 02,
// c0, a8, 00, 01,
// 00, 50, c5, 32, 00, 00, 00, 00, a8, 95, 1c, 32, 50, 02]
