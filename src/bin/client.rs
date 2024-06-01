extern crate robust_verifiable_dp as dp;
extern crate rvdp_statistical_system as dpsys;

use dp::public_parameters::PublicParameters;
use dp::client::Client;
use dp::msg_structs::ComsAndShare;
use std::net::SocketAddr;
use dpsys::shared::structs::{Config};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};



pub fn client(conf_str:&str,address:&str,inputs:Vec<bool> ,id:usize){



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

    //创建Client实例
    let mut client_types:Vec<Client> = Vec::new();
    for i in 0..types {
        client_types.push(Client::new(id, inputs[i], &pp, ));
    }

    let sigs_prover_type: Arc<Mutex<Vec<Vec<Option<Ed25519Signature>>>>> = Arc::new(Mutex::new(vec![vec![None; config.num_provers]; config.types]));

    //发送commitments
    for i in 0..socket_addresses.len() {
        let addr = socket_addresses[i];
        let msg_vec: Vec<ComsAndShare> = client_types.iter().map(|c| c.create_prover_msg(&pp, i)).collect();
        let data = bcs::to_bytes(&msg_vec).expect("Failed to serialize data");
    
        // Clone the Arc to share it between tasks
        let sigs_prover_type_clone = Arc::clone(&sigs_prover_type);
    
        tokio::spawn(async move {
            // Lock the Mutex and get the guard
            let sigs_prover_type_guard = sigs_prover_type_clone.lock().await;
            connect_and_communicate(addr, data, &sigs_prover_type_guard[i]).await;
        });
    }
    
    
}


use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::{Duration, timeout};

async fn connect_and_communicate(addr: SocketAddr, data: Vec<u8>, mut sigs: &Vec<Option<Ed25519Signature>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr).await?;

    // 发送数据
    stream.write_all(&data).await?;

    // 设置接收数据的超时时间
    let mut buffer = vec![0; 1024];
    let read_result = timeout(Duration::from_secs(5), stream.read(&mut buffer)).await;
    
    match read_result {
        Ok(Ok(bytes_read)) => {
            println!("Received {} bytes: {:?}", bytes_read, &buffer[..bytes_read]);
        }
        Ok(Err(e)) => {
            eprintln!("Failed to read from socket: {}", e);
        }
        Err(_) => {
            eprintln!("Timeout when reading from socket");
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
    let inputs = vec![true, false, true, false, true, false, true, false, true, false, true, false, true, false, true];
    client(&conf_str,&address,inputs, 1);


}