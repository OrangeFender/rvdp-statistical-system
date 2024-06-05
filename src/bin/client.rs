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
use std::fs::File;
use std::io::Read;

use std::env;

const N_B: usize = 10;
// NUM_PROVERS >= 2*THRESHOLD + 1
const NUM_PROVERS: usize = 7;
const THRESHOLD: usize = 3;
const TYPES: usize = 3;

const PROVER_ADDRESSES: [&str; 7] = [
    "127.0.0.1:8000",
    "127.0.0.1:8001",
    "127.0.0.1:8002",
    "127.0.0.1:8003",
    "127.0.0.1:8004",
    "127.0.0.1:8005",
    "127.0.0.1:8006",
];

const VERIFIER_ADDRESS: &str = "127.0.0.1:10000";

pub async fn client(client_types:Vec<Client>,key:Vec<Ed25519PublicKey>,sigs_prover_type:Arc<RwLock<Vec<Vec<Option<Ed25519Signature>>>>>,pp:PublicParameters){
    //发送commitments
    for i in 0..NUM_PROVERS {
        let addr: &str = PROVER_ADDRESSES[i];
        let msg_vec: Vec<ComsAndShare> = client_types.iter().map(|c| c.create_prover_msg(&pp, i)).collect();
        let data = bcs::to_bytes(&msg_vec).expect("Failed to serialize data");
    
        // Clone the Arc to share it between tasks
        let sigs_prover_type_clone = Arc::clone(&sigs_prover_type);
    
        tokio::spawn(async move {
            // Lock the Mutex and get the guard
            let mut sigs_prover_type_guard = sigs_prover_type_clone.write().await;
            if let Err(e) = connect_and_communicate(addr, data, &mut sigs_prover_type_guard[i],TYPES).await {
                eprintln!("Failed to connect and communicate: {}", e);
            }
        });
    }
    let sigs_prover_type_guard = sigs_prover_type.read().await;
    
    let mut transcripts=Vec::new();
    for j in 0..TYPES {
        let mut validvec: Vec<bool> = vec![false; NUM_PROVERS]; 
        let mut sigs = Vec::new();    
        for i in 0..NUM_PROVERS {
            let pk= key[i].clone();
            if sigs_prover_type_guard[i][j].is_some() {
                let signature = sigs_prover_type_guard[i][j].as_ref().unwrap();
                let ret=client_types[j].vrfy_sig(&pk, signature);
                if ret {
                    sigs.push((signature.clone(),i));
                    validvec[i] = true;
                }
            }
        }
        transcripts.push(client_types[j].get_transcript(NUM_PROVERS, &validvec, sigs.clone()));
    }
// 向verifier发送transcripts
    let mut buffer = Vec::new();
    let bytes= bcs::to_bytes(&transcripts.clone()).expect("Failed to serialize transcripts");
    buffer.extend_from_slice(&bytes);
    let mut stream = TcpStream::connect(VERIFIER_ADDRESS).await.expect("Failed to connect to verifier");
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

async fn connect_and_communicate(addr: &str, data: Vec<u8>, sigs: &mut Vec<Option<Ed25519Signature>>,type_num:usize) -> Result<(), Box<dyn std::error::Error>> {
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
    let args: Vec<String> = env::args().collect();
    if args.len() != TYPES + 2 {
        eprintln!("Error: The number of arguments must be equal to TYPES + 1");
        return;
    }

    let mut inputs = Vec::new();
    for i in 1..=TYPES {
        match args[i].as_str() {
            "0" => inputs.push(false),
            "1" => inputs.push(true),
            _ => {
                eprintln!("Error: Invalid argument. Only 0 (for false) and 1 (for true) are allowed");
                return;
            }
        }
    }

    let num: u64 = match args[TYPES + 1].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Error: Invalid argument. The last argument must be a u64 number");
            return;
        }
    };


    let pp = PublicParameters::new(
        N_B, NUM_PROVERS, THRESHOLD, b"seed"
    );

    // 读取公钥文件
    let mut key_file = File::open(format!("pks")).unwrap();
    let mut bytes = Vec::new();
    key_file.read_to_end(&mut bytes).unwrap();
    let key:Vec<Ed25519PublicKey> = bcs::from_bytes(&bytes).unwrap();

    //创建Client实例
    let mut client_types:Vec<Client> = Vec::new();
    for i in 0..TYPES {
        client_types.push(Client::new(num, inputs[i], &pp, ));
    }

    let sigs_prover_type: Arc<RwLock<Vec<Vec<Option<Ed25519Signature>>>>> = Arc::new(RwLock::new(vec![vec![None; NUM_PROVERS]; TYPES]));
    println!("Client {} started", num);

    client(client_types,key,sigs_prover_type,pp);


}