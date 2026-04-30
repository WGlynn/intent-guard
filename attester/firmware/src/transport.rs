// USB CDC transport. The ESP32-S3 has a built-in USB serial/JTAG controller
// that exposes a CDC ACM device when plugged in. The host bridge (in
// attester/host) talks to it as a regular serial port.
//
// This module is the framing + minicbor decode/encode wrapper around that.
// Wire format matches attester/SPEC.md §3.

use alloc::vec::Vec;
use crate::protocol::{Message, ProposeIntent};
use crate::crypto::Network;

const MAGIC: [u8; 2] = [0xa7, 0x77];

pub struct UsbCdc {
    rx_buf: Vec<u8>,
    // ESP32-S3 USB serial peripheral handle would live here.
    _placeholder: (),
}

#[derive(Debug)]
pub enum TransportError {
    Eof,
    BadMagic,
    BadCrc,
    Decode,
}

impl UsbCdc {
    pub fn open() -> Self {
        Self { rx_buf: Vec::new(), _placeholder: () }
    }

    pub fn recv<'a>(&'a mut self) -> Result<Message<'a>, TransportError> {
        // Loop: pull bytes from the USB peripheral into rx_buf, attempt
        // to unframe, decode minicbor, return Message. Real impl reads in
        // chunks via interrupt/poll; this skeleton sketches the shape.
        loop {
            if let Some(payload) = self.try_unframe()? {
                let msg = decode_message(&payload)?;
                return Ok(msg);
            }
            self.read_more()?;
        }
    }

    pub fn send(&mut self, _msg: Message) -> Result<(), TransportError> {
        // Real impl: minicbor::to_vec, frame with magic + length + crc, write to USB.
        Ok(())
    }

    fn try_unframe(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        if self.rx_buf.len() < 8 {
            return Ok(None);
        }
        if self.rx_buf[0] != MAGIC[0] || self.rx_buf[1] != MAGIC[1] {
            // Resync by dropping one byte.
            self.rx_buf.drain(0..1);
            return Err(TransportError::BadMagic);
        }
        let length = ((self.rx_buf[2] as usize) << 8) | (self.rx_buf[3] as usize);
        let total = 4 + length + 4;
        if self.rx_buf.len() < total {
            return Ok(None);
        }
        let frame = self.rx_buf.drain(..total).collect::<Vec<u8>>();
        let payload = frame[4..4 + length].to_vec();
        let crc_bytes: [u8; 4] = frame[4 + length..].try_into().unwrap();
        let expected = u32::from_be_bytes(crc_bytes);
        let actual = crc32(&frame[..4 + length]);
        if expected != actual {
            return Err(TransportError::BadCrc);
        }
        Ok(Some(payload))
    }

    fn read_more(&mut self) -> Result<(), TransportError> {
        // Real impl: blocking read from USB peripheral. Stubbed.
        Err(TransportError::Eof)
    }
}

fn decode_message<'a>(payload: &'a [u8]) -> Result<Message<'a>, TransportError> {
    // Skeleton: real implementation uses minicbor::decode to parse the CBOR
    // map and construct the appropriate Message variant. We sketch the
    // structure for ProposeIntent because that's the most complex.
    if payload.is_empty() {
        return Err(TransportError::Decode);
    }
    // Pretend we successfully parsed a Hello as a placeholder for the skeleton.
    Ok(Message::Hello)
}

#[allow(dead_code)]
fn build_propose<'a>(
    proposal_id: [u8; 16],
    network: &str,
    vault: Vec<u8>,
    nonce: u64,
    action_kind: u32,
    action_args: &'a [u8],
    intent_hash: [u8; 32],
    signed_at: u64,
    expires_at: u64,
) -> Result<Message<'a>, TransportError> {
    Ok(Message::ProposeIntent(ProposeIntent {
        proposal_id,
        network: Network::from_str(network).ok_or(TransportError::Decode)?,
        vault,
        nonce,
        action_kind,
        action_args,
        intent_hash,
        signed_at,
        expires_at,
    }))
}

fn crc32(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xffffffff;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & (!(crc & 1)).wrapping_add(1));
        }
    }
    crc ^ 0xffffffff
}
