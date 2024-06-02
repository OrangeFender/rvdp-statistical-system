extern crate robust_verifiable_dp as dp;
extern crate rvdp_statistical_system as dpsys;

use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use dp::msg_structs::ComsAndShare;
use dp::sig::*;
use blstrs::{G1Projective, Scalar};
use std::net::SocketAddr;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task;
use serde::{Serialize, Deserialize};
use bcs::{to_bytes, from_bytes};

type SharedMap = Arc<RwLock<HashMap<u64, (Scalar, Scalar)>>>;
type SharedProvers = Arc<Vec<Prover>>;

const N_B: usize = 10;
const NUM_CLIENTS: usize = 15;
// NUM_PROVERS >= 2*THRESHOLD + 1
const NUM_PROVERS: usize = 7;
const THRESHOLD: usize = 3;

#[tokio::main]
async fn main() {
    // 共享资源，用于存放<share, pi>
    let share_hashmap: SharedMap = Arc::new(RwLock::new(HashMap::new()));

    prover(share_hashmap).await;

    // // 启动两个新的异步任务，它会调用各自的函数，并传递共享的share_hashmap克隆副本作为参数。tokio::spawn会将这个任务放入Tokio的任务调度器中进行调度和执行。
    // let clients_handle = tokio::spawn(clients_connection(share_hashmap.clone()));
    // let verifier_handle = tokio::spawn(verifier_connection(share_hashmap.clone()));

    // 服务器一直运行，直到终端给出kill命令
    tokio::signal::ctrl_c().await.unwrap();
    println!("Shutting down");
}

// 实例化多个prover是为了模拟不同的类型疾病；开NUM_PROVERS个程序，一个程序模拟一个prover
async fn prover(share_hashmap: SharedMap) {
    // 生成公共参数
    let pp = PublicParameters::new(
        N_B, NUM_PROVERS, THRESHOLD, b"seed"
    );

    // 生成签名公私钥
    // 公钥如何分发？
    let sig_keys = generate_ed_sig_keys(NUM_PROVERS);

    // 生成服务器实例
    // let mut provers_vector: Vec<Prover> = Vec::new();  // 创建provers的实例
    let provers = Arc::new(provers_vector);  // 将 provers_vector 放入 Arc 中
    for i in 0..NUM_PROVERS {
        provers_vector.push(Prover::new(i, &pp, sig_keys[i].private_key.clone(), sig_keys[i].public_key.clone()))
    }

    // 启动两个新的异步任务，它会调用各自的函数，并传递共享的share_hashmap克隆副本作为参数。tokio::spawn会将这个任务放入Tokio的任务调度器中进行调度和执行。
    tokio::spawn(clients_connection(share_hashmap.clone()));
    tokio::spawn(verifier_connection(share_hashmap.clone()));

}

// 监听clients连接
async fn clients_connection(share_hashmap: SharedMap, ) {
    for i in 0..NUM_PROVERS {
        let addr = format!("127.0.0.1:{}", 8000 + i);  // 这里改为提前定好的socket
        let listener = TcpListener::bind(&addr).await.unwrap();  // 每个prover监听不同的socket
        println!("Listening for clients on {}", addr);

        let hashmap_clone = share_hashmap.clone();
        // 持续接收clients数据
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                handle_client(socket, hashmap_clone.clone()).await;
            }
        });
    }

}

// 处理client连接
async fn handle_client(mut socket: TcpStream, share_hashmap: SharedMap) {
    let mut buffer = Vec::new();
    socket.read_to_end(&mut buffer).await.unwrap();
    let com_and_share: ComsAndShare = from_bytes(&buffer).unwrap();  // com_and_share为接收到的ComsAndShare类型数据

    // Assuming verify_msg_and_sig function is defined and returns a boolean or some result
    // 做verify_msg_and_sig验证+签名
    let verification_result = verify_msg_and_sig(&com_and_share);
    
    let mut hashmap = share_hashmap.write().await;  // 获得写锁
    hashmap.insert(com_and_share.id, (com_and_share.share, com_and_share.pi));

    // 将签名返回clients
    let response = to_bytes(&verification_result).unwrap();
    socket.write_all(&response).await.unwrap();
}

// 监听verifier连接
async fn verifier_connection(share_hashmap: SharedMap) {
    for i in 0..NUM_PROVERS {
        let addr = format!("127.0.0.1:{}", 9000 + i);  // 这里改为提前定好的socket
        let listener = TcpListener::bind(&addr).await.unwrap();
        println!("Listening for verifiers on {}", addr);

        let hashmap_clone = share_hashmap.clone();
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                handle_verifier(socket, hashmap_clone.clone()).await;
            }
        });
    }
}

async fn handle_verifier(mut socket: TcpStream, share_hashmap: SharedMap) {
    let mut buffer = Vec::new();
    socket.read_to_end(&mut buffer).await.unwrap();
    let valid_ids: Vec<u64> = from_bytes(&buffer).unwrap();

    let mut results = Vec::new();

    let hashmap = share_hashmap.read().await;

    // 这里获取了value之后，应该还需要发送其他的数据
    for id in valid_ids {
        if let Some(value) = hashmap.get(&id) {
            results.push((id, value.clone()));
        }
    }

    let response = to_bytes(&results).unwrap();
    socket.write_all(&response).await.unwrap();
}
