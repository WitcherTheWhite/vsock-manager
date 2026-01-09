use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use bincode::{config, decode_from_slice};
use dashmap::DashSet;
use mbedtls::error::codes;
use mbedtls::rng::{CtrDrbg, OsEntropy};
use mbedtls::ssl::CipherSuite::{
    DhePskWithSm4128GcmSm3, EcdhePskWithSm4128GcmSm3, PskWithSm4128GcmSm3, RsaPskWithSm4128GcmSm3,
};
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context, Version};
use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

use crate::pks::{generate_psk, get_psk_identity};
use crate::protocal::TeeRequest;
use crate::vsock_define::VSOCK_PORT;
use crate::vsock_protocal::{CHUNK_SIZE, PacketHeader};

pub fn run_vsock_server(registry: Arc<DashSet<String>>) -> anyhow::Result<()> {
    println!("Vsock server is running...");

    let entropy = OsEntropy::new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cipher_suites: Vec<i32> = vec![
        PskWithSm4128GcmSm3.into(),
        DhePskWithSm4128GcmSm3.into(),
        RsaPskWithSm4128GcmSm3.into(),
        EcdhePskWithSm4128GcmSm3.into(),
        0,
    ];
    let psk = generate_psk()?;
    let psk_identity = get_psk_identity();
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

    config.set_rng(rng);
    config.set_min_version(Version::Tls1_2)?;
    config.set_max_version(Version::Tls1_2)?;
    config.set_ciphersuites(Arc::new(cipher_suites));
    config.set_psk(&psk, psk_identity)?;
    let rc_config = Arc::new(config);

    let addr = VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT);
    let listener = VsockListener::bind(&addr)?;

    for stream in listener.incoming() {
        let stream = stream?;
        thread::spawn({
            let registry = registry.clone();
            let config = rc_config.clone();
            move || {
                if let Err(e) = handle_vsock_request(stream, registry.clone(), config) {
                    eprintln!("Failed to handle vsock request: {:?}", e);
                }
            }
        });
    }

    Ok(())
}

pub fn handle_vsock_request(
    stream: VsockStream,
    registry: Arc<DashSet<String>>,
    config: Arc<Config>,
) -> anyhow::Result<()> {
    let mut ctx = Context::new(config.clone());
    ctx.establish(stream, None)?;
    let mut session_uuid: Option<String> = None;

    loop {
        let mut header = [0; PacketHeader::SIZE];

        if ctx.io_mut().is_none() {
            break;
        }

        ctx.read_exact(&mut header)?;

        handle_packet(
            &mut ctx,
            PacketHeader::from_bytes(&header),
            &mut session_uuid,
        )?;

        thread::sleep(std::time::Duration::from_millis(1));
    }

    ctx.close();

    Ok(())
}

fn handle_packet(
    ctx: &mut Context<VsockStream>,
    header: PacketHeader,
    session_uuid: &mut Option<String>,
) -> anyhow::Result<()> {
    let mut data = vec![0u8; header.data_size as usize];
    recv_data(ctx, &mut data)?;

    let (req, _): (TeeRequest, _) = decode_from_slice(&data, config::standard())?;
    let uuid = match req {
        TeeRequest::OpenSession { uuid, .. } => {
            *session_uuid = Some(uuid.clone());
            uuid
        }
        _ => session_uuid.as_ref().unwrap().clone(),
    };

    let path = format!("/tmp/{}.sock", uuid);
    let mut stream = UnixStream::connect(path)?;
    let mut message = Vec::with_capacity(4 + data.len());
    message.extend_from_slice(&(data.len() as u32).to_ne_bytes());
    message.extend_from_slice(&data);
    stream.write_all(&message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    send_data(ctx, &len_buf)?;

    let len = u32::from_ne_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp)?;
    send_data(ctx, &resp)?;

    Ok(())
}

fn recv_data(ctx: &mut Context<VsockStream>, data: &mut [u8]) -> mbedtls::Result<()> {
    let total = data.len();
    let chunk_size = CHUNK_SIZE as usize;

    let tmp = [1u8; 4];

    if total <= chunk_size {
        ctx.read_exact(data).map_err(|_| codes::NetRecvFailed)?;
        ctx.write_all(&tmp).map_err(|_| codes::NetSendFailed)?;
    } else {
        let mut offset: usize = 0;
        while offset < total {
            let chunk_size = (total - offset).min(chunk_size);
            ctx.read_exact(&mut data[offset..offset + chunk_size])
                .map_err(|_| codes::NetRecvFailed)?;
            ctx.write_all(&tmp).map_err(|_| codes::NetSendFailed)?;
            offset += chunk_size;
        }
    }

    Ok(())
}

fn send_data(ctx: &mut Context<VsockStream>, data: &[u8]) -> mbedtls::Result<()> {
    let total = data.len();
    let chunk_size = CHUNK_SIZE as usize;

    if total <= chunk_size {
        ctx.write_all(data).map_err(|_| codes::NetSendFailed)?;
    } else {
        for chunk in data.chunks(chunk_size) {
            ctx.write_all(chunk).map_err(|_| codes::NetSendFailed)?;
        }
    }

    Ok(())
}
