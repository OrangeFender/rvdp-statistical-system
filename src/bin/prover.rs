extern crate robust_verifiable_dp as dp;
extern crate rvdp_statistical_system as dpsys;

use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use dp::msg_structs::ComsAndShare;
use dp::hash_xor::*;
use blstrs:: Scalar;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519Signature};

use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use bcs::{to_bytes, from_bytes};
use std::fs::File;
use std::io::Read;
type SharedMap = Arc<RwLock<HashMap<u64, Vec<(Scalar, Scalar)>>>>;

use std::env;


const N_B: usize = 10;
// NUM_PROVERS >= 2*THRESHOLD + 1
const NUM_PROVERS: usize = 7;
const THRESHOLD: usize = 3;
const TYPES: usize = 3;
#[tokio::main]
async fn main() {
    
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Please provide a number as argument");
        std::process::exit(1);
    }
    let ind: usize = match args[1].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Failed to parse number");
            std::process::exit(1);
        }
    };

    // 共享资源，用于存放<share, pi>
    let share_hashmap: SharedMap = Arc::new(RwLock::new(HashMap::new()));

    let mut key_file = File::open(format!("sk{}",ind)).unwrap();
    let mut bytes = Vec::new();
    key_file.read_to_end(&mut bytes).unwrap();
    let key:Ed25519PrivateKey = from_bytes(&bytes).unwrap();
    let mut boolvecvec_file = File::open(format!("boolvecvec{}",ind)).unwrap();
    let mut boolvecvec_bytes = Vec::new();
    boolvecvec_file.read_to_end(&mut boolvecvec_bytes).unwrap();
    let boolvecvec: Vec<Vec<bool>> = from_bytes(&boolvecvec_bytes).unwrap();

    // 读取并反序列化Scalarvecvec
    let mut Scalarvecvec_file = File::open(format!("Scalarvecvec{}",ind)).unwrap();
    let mut Scalarvecvec_bytes = Vec::new();
    Scalarvecvec_file.read_to_end(&mut Scalarvecvec_bytes).unwrap();
    let Scalarvecvec: Vec<Vec<Scalar>> = from_bytes(&Scalarvecvec_bytes).unwrap();

    prover(share_hashmap,key,boolvecvec,Scalarvecvec,ind).await;

    // // 启动两个新的异步任务，它会调用各自的函数，并传递共享的share_hashmap克隆副本作为参数。tokio::spawn会将这个任务放入Tokio的任务调度器中进行调度和执行。
    // let clients_handle = tokio::spawn(clients_connection(share_hashmap.clone()));
    // let verifier_handle = tokio::spawn(verifier_connection(share_hashmap.clone()));

    // 服务器一直运行，直到终端给出kill命令
    tokio::signal::ctrl_c().await.unwrap();
    println!("Shutting down");
}

// 实例化多个prover是为了模拟不同的类型疾病；开NUM_PROVERS个程序，一个程序模拟一个prover
async fn prover(share_hashmap: SharedMap,key:Ed25519PrivateKey, boolvecvec:Vec<Vec<bool>>, Scalarvecvec:Vec<Vec<Scalar>>,ind: usize) {
    // 生成公共参数
    let pp = PublicParameters::new(
        N_B, NUM_PROVERS, THRESHOLD, b"seed"
    );


    // 生成服务器实例
    let mut provers_vector: Vec<Prover> = Vec::new();  // 创建provers的实例
    for i in 0..TYPES {
        provers_vector.push(Prover::new(ind, boolvecvec[i].clone(),Scalarvecvec[i].clone(),&pp, key.clone()))
    }

    // 启动两个新的异步任务，它会调用各自的函数，并传递共享的share_hashmap克隆副本作为参数。tokio::spawn会将这个任务放入Tokio的任务调度器中进行调度和执行。
    tokio::spawn(clients_connection(share_hashmap.clone(),provers_vector.clone(),pp.clone(),ind));
    tokio::spawn(verifier_connection(share_hashmap.clone(),provers_vector.clone(),pp.clone(),ind));

}

// 监听clients连接
async fn clients_connection(share_hashmap: SharedMap,provervec: Vec<Prover>,pp:PublicParameters,ind: usize) {
    let addr = format!("127.0.0.1:{}", 8000+ind);  // 这里改为提前定好的socket
    let listener = TcpListener::bind(&addr).await.unwrap();  // 每个prover监听不同的socket
    println!("Listening for clients on {}", addr);
    let hashmap_clone = share_hashmap.clone();
    // 持续接收clients数据
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            handle_client(socket, hashmap_clone.clone(),provervec[0].clone(),&pp).await;
        }
    });
}

// 处理client连接
async fn handle_client(mut socket: TcpStream, share_hashmap: SharedMap,prover: Prover,pp:&PublicParameters) {
    println!("Handling client");
    let mut buffer = Vec::new();
    socket.read_to_end(&mut buffer).await.unwrap();
    let com_and_share_vec: Vec<ComsAndShare> = from_bytes(&buffer).unwrap();  // com_and_share为接收到的ComsAndShare类型数据
    let id= com_and_share_vec[0].id;
    // Assuming verify_msg_and_sig function is defined and returns a boolean or some result
    // 做verify_msg_and_sig验证+签名
    let mut sharevec:Vec<(Scalar,Scalar)> = Vec::new();
    let mut sigs:Vec<Ed25519Signature> = Vec::new();
    for com_and_share in com_and_share_vec {
        let verification_result = prover.verify_msg_and_sig(&com_and_share,&pp);
        match verification_result {
            Some(signature) => {
                sharevec.push((com_and_share.share, com_and_share.pi));
                sigs.push(signature);
                //println!("Verification succeeded");
            },
            None => {
                println!("Verification failed");
                return;
            }
        }
    }
    
    let mut hashmap = share_hashmap.write().await;  // 获得写锁
    hashmap.insert(id, sharevec);  // 将sharevec插入hashmap);

    // 将签名返回clients
    let response = to_bytes(&sigs).unwrap();
    socket.write_all(&response).await.unwrap();
}

// 监听verifier连接
async fn verifier_connection(share_hashmap: SharedMap,provervec: Vec<Prover>,pp:PublicParameters,ind: usize) {
    let addr = format!("127.0.0.1:{}",9000+ ind);  // 这里改为提前定好的socket
    let listener = TcpListener::bind(&addr).await.unwrap();
    println!("Listening for verifiers on {}", addr);

    let hashmap_clone = share_hashmap.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            handle_verifier(socket, hashmap_clone.clone(),provervec.clone(),&pp).await;
        }
    });
    
}

async fn handle_verifier(mut socket: TcpStream, share_hashmap: SharedMap,mut provervec: Vec<Prover>,pp:&PublicParameters) {
    let mut buffer = Vec::new();
    socket.read_to_end(&mut buffer).await.unwrap();
    let valid_ids: Vec<u64> = from_bytes(&buffer).unwrap();

    let hash= hash_T_to_bit_array(valid_ids.clone(), pp.get_n_b());
    for i in 0..provervec.len() {
        provervec[i].x_or(&pp, &hash);
    }

    let mut results: Vec<Vec<(Scalar,Scalar)>> = Vec::new();

    let hashmap = share_hashmap.read().await;

    // 这里获取了value之后，应该还需要发送其他的数据
    for id in valid_ids {
        if let Some(value) = hashmap.get(&id) {
            results.push(value.clone());
        }
    }
    let results_type_id = transpose(&results);

    let mut output:Vec<(Scalar,Scalar)> =Vec::new();

    for i in 0..TYPES {
        output.push(provervec[i].calc_output_with_share(pp, results_type_id[i].clone()));
    }


    let response = to_bytes(&output).unwrap();
    socket.write_all(&response).await.unwrap();
}

fn transpose<T: Clone>(v: &Vec<Vec<T>>) -> Vec<Vec<T>> {
    let mut result = vec![vec![v[0][0].clone(); v.len()]; v[0].len()];

    for i in 0..v.len() {
        for j in 0..v[i].len() {
            result[j][i] = v[i][j].clone();
        }
    }

    result
}