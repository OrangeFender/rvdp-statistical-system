extern crate robust_verifiable_dp as dp;
extern crate rvdp_statistical_system as dpsys;

use dp::public_parameters::PublicParameters;
use dp::client::Client;
use dp::msg_structs::ComsAndShare;
use std::net::SocketAddr;
use dpsys::shared::structs::{Config};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};



pub async fn client(conf_str:&str,address:&str,pks:&[u8],inputs:Vec<bool> ,id:u64){
    let mut pp:PublicParameters;
    let types:usize;
    //从json中生成公共参数
    let mut config;
    match serde_json::from_str::<Config>(conf_str) {
        Ok(c) => {
            pp = PublicParameters::new(
                c.n_b, c.num_provers, c.threshold, c.seed.as_bytes()
                );
            types = c.types;
            config = c;
        },
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    }

    //检查input长度
    if inputs.len() != types {
        println!("Error: input length does not match the number of types");
        return;
    }

    let v: serde_json::Value = serde_json::from_str(address).unwrap();
    let mut socket_addresses = Vec::new();

    if let Some(ip_addresses) = v["ip_addresses"].as_array() {
        for ip in ip_addresses {
            if let Some(ip_str) = ip.as_str() {
                if let Ok(socket_addr) = ip_str.parse::<SocketAddr>() {
                    socket_addresses.push(socket_addr);
                }
            }
        }
    }
    //反序列化公钥
    let mut sig_keys: Vec<Ed25519PublicKey> = bcs::from_bytes(pks).expect("Failed to deserialize public keys");


    //创建Client实例
    let mut client_types:Vec<Client> = Vec::new();
    for i in 0..types {
        client_types.push(Client::new(id, inputs[i], &pp, ));
    }

    let sigs_prover_type: Arc<RwLock<Vec<Vec<Option<Ed25519Signature>>>>> = Arc::new(RwLock::new(vec![vec![None; config.num_provers]; config.types]));

    //发送commitments
    for i in 0..socket_addresses.len() {
        let addr = socket_addresses[i];
        let msg_vec: Vec<ComsAndShare> = client_types.iter().map(|c| c.create_prover_msg(&pp, i)).collect();
        let data = bcs::to_bytes(&msg_vec).expect("Failed to serialize data");
    
        // Clone the Arc to share it between tasks
        let sigs_prover_type_clone = Arc::clone(&sigs_prover_type);
    
        tokio::spawn(async move {
            // Lock the Mutex and get the guard
            let mut sigs_prover_type_guard = sigs_prover_type_clone.write().await;
            if let Err(e) = connect_and_communicate(addr, data, &mut sigs_prover_type_guard[i],config.types).await {
                eprintln!("Failed to connect and communicate: {}", e);
            }
        });
    }
    let sigs_prover_type_guard = sigs_prover_type.read().await;
    
    let mut transcripts=Vec::new();
    for j in 0..config.types {
        let mut validvec: Vec<bool> = vec![false; config.num_provers]; 
        let mut sigs = Vec::new();    
        for i in 0..config.num_provers {
            let pk= sig_keys[i].clone();
            if sigs_prover_type_guard[i][j].is_some() {
                let signature = sigs_prover_type_guard[i][j].as_ref().unwrap();
                let ret=client_types[j].vrfy_sig(&pk, signature);
                if ret {
                    sigs.push((signature.clone(),i));
                    validvec[i] = true;
                }
            }
        }
        transcripts.push(client_types[j].get_transcript(config.num_provers, &validvec, sigs.clone()));
    }
// 向verifier发送transcripts
    let mut buffer = Vec::new();
    let bytes= bcs::to_bytes(&transcripts.clone()).expect("Failed to serialize transcripts");
    buffer.extend_from_slice(&bytes);
    let mut stream = TcpStream::connect(socket_addresses[0]).await.expect("Failed to connect to verifier");
    stream.write_all(&buffer).await.expect("Failed to send transcripts");

    // 读取对方发来的返回消息
    let mut response = String::new();
    stream.read_to_string(&mut response).await.expect("Failed to read response");

    // 检查返回消息是否为 "OK"
    if response.trim() == "OK" {
        println!("Received OK from verifier");
    } else {
        eprintln!("Received unexpected response from verifier: {}", response);
    }
}


use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::{Duration, timeout};

async fn connect_and_communicate(addr: SocketAddr, data: Vec<u8>, sigs: &mut Vec<Option<Ed25519Signature>>,type_num:usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr).await?;

    // 发送数据
    stream.write_all(&data).await?;

    // 设置接收数据的超时时间
    let mut buffer = vec![0; 1024*type_num];
    let read_result = timeout(Duration::from_secs(15), stream.read(&mut buffer)).await;
    
    match read_result {
        Ok(Ok(bytes_read)) => {
            // Deserialize the received data
            let sigs_received: Vec<Ed25519Signature> = bcs::from_bytes(&buffer[..bytes_read]).expect("Failed to deserialize data");
            for i in 0..type_num {
                sigs[i] = Some(sigs_received[i].clone());
            }
        }
        Ok(Err(e)) => {
            //eprintln!("Failed to read from socket: {}", e);
            // Do nothing, because sig[i] is already None
        }
        Err(_) => {
            //eprintln!("Timeout when reading from socket");
            //无需做任何处理，因为原本sig[i]就是None
        }
    }
    Ok(())
}

fn main(){
    let conf_str=r#"
    {
        “types":15,
        "n_b": 10,
        "num_provers": 10,
        "threshold": 4,
        "seed": "seed1001",
    }
"#;

    let address = r#"
{
    "ip_addresses": [
        "192.168.0.1:1234",
        "192.168.0.2:1234",
        "10.0.0.1:1234",
        "172.16.0.1:1234"
    ]
}
"#;

    let pks = "substutute the public keys here".as_bytes();

    let inputs = vec![true, false, true, false, true, false, true, false, true, false, true, false, true, false, true];
    client(&conf_str,&address,pks,inputs, 1);


}