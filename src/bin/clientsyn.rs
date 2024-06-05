extern crate robust_verifiable_dp as dp;
extern crate rvdp_statistical_system as dpsys;

use dp::public_parameters::PublicParameters;
use dp::client::Client;
use dp::msg_structs::ComsAndShare;
use dp::sig::verify_sig;
use std::net::SocketAddr;
use dpsys::shared::structs::Config;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

use std::sync::{Arc, RwLock};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::env;
use std::thread;

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

pub fn client(client_types: Vec<Client>, key: Vec<Ed25519PublicKey>, sigs_prover_type: Arc<RwLock<Vec<Vec<Option<Ed25519Signature>>>>>, pp: PublicParameters) {
    let mut handles = vec![];

    for i in 0..NUM_PROVERS {
        let addr: &str = PROVER_ADDRESSES[i];
        let msg_vec: Vec<ComsAndShare> = client_types.iter().map(|c| c.create_prover_msg(&pp, i)).collect();
        let key_clone = key[i].clone();
        let sigs_prover_type_clone = Arc::clone(&sigs_prover_type);
        let handle = thread::spawn(move || {
            //获取读写锁的写锁
            let mut sigs_prover_type_guard = sigs_prover_type_clone.write().unwrap();
            let sigs_prover = &mut sigs_prover_type_guard[i];
            if let Err(e) = connect_and_communicate(addr, msg_vec, sigs_prover, &key_clone) {
                eprintln!("Failed to connect and communicate: {}", e);
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to finish
    for handle in handles {
        handle.join().unwrap();
    }

    let sigs_prover_type_guard = sigs_prover_type.read().unwrap();

    let mut transcripts = Vec::new();
    for j in 0..TYPES {
        let mut validvec: Vec<bool> = vec![false; NUM_PROVERS];
        let mut sigs = Vec::new();
        for i in 0..NUM_PROVERS {
            let pk = key[i].clone();
            if let Some(signature) = &sigs_prover_type_guard[i][j] {
                let ret = client_types[j].vrfy_sig(&pk, signature);
                if ret {
                    sigs.push((signature.clone(), i));
                    validvec[i] = true;
                }
            }
        }
        transcripts.push(client_types[j].get_transcript(NUM_PROVERS, &validvec, sigs.clone()));
    }

    // 向verifier发送transcripts
    let mut stream = TcpStream::connect(VERIFIER_ADDRESS).expect("Failed to connect to verifier");

    for transcript in &transcripts {
        let mut buffer = Vec::new();
        let bytes = bcs::to_bytes(transcript).expect("Failed to serialize transcript");
        buffer.extend_from_slice(&bytes);
        //println!("length: {}", buffer.len());
        stream.write_all(&buffer).expect("Failed to send transcript");
    }

    // 读取对方发来的返回消息
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("Failed to read response");

    // 将字节转换为字符串
    let response = String::from_utf8(response).expect("Failed to convert response to string");

    // 检查返回消息是否为 "OK"
    if response.trim() == "OK" {
        println!("Received OK from verifier");
    } else {
        eprintln!("Received unexpected response from verifier: {}", response);
    }
}

fn connect_and_communicate(addr: &str, msg_vec: Vec<ComsAndShare>, sigs: &mut Vec<Option<Ed25519Signature>>, pk:&Ed25519PublicKey) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr)?;
    let msgvecclone = msg_vec.clone();
    for msg in msg_vec {
        let data = bcs::to_bytes(&msg).expect("Failed to serialize data");
        //println!("length: {}", data.len());
        stream.write_all(&data)?;
    }
    // 发送数据
    //stream.write_all(&data)?;

    // 设置接收数据的超时时间
    //let mut sigs: Vec<Ed25519Signature> = Vec::new();
    let mut buffer = vec![0; 65]; // 假设Ed25519Signature的大小为65字节

    for i in 0..TYPES {
        match stream.read_exact(&mut buffer) {
            Ok(_) => {
                let sig: Ed25519Signature = bcs::from_bytes(&buffer).unwrap();
                //sigs.push(sig);
                if verify_sig(&msgvecclone[i].coms, pk, sig.clone()){
                    sigs[i] = Some(sig);
                    //println!("Verification succeeded");
                
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    // 如果在读取数据时超时，退出循环
                    break;
                } else {
                    // 如果发生其他错误，直接返回错误
                    return Err(Box::new(e));
                }
            }
        }
    }
    Ok(())
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() != TYPES + 2 {
        eprintln!("Error: The number of arguments must be equal to TYPES + 1");
        args=vec!["".to_string(),"1".to_string(),"1".to_string(),"1".to_string(),"3654".to_string()];
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
    let key: Vec<Ed25519PublicKey> = bcs::from_bytes(&bytes).unwrap();

    // 创建Client实例
    let mut client_types: Vec<Client> = Vec::new();
    for i in 0..TYPES {
        client_types.push(Client::new(num, inputs[i], &pp));
    }

    let sigs_prover_type: Arc<RwLock<Vec<Vec<Option<Ed25519Signature>>>>> = Arc::new(RwLock::new(vec![vec![None; TYPES]; NUM_PROVERS]));
    println!("Client {} started", num);

    client(client_types, key, sigs_prover_type, pp);
}
