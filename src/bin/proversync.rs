extern crate robust_verifiable_dp as dp;
extern crate rvdp_statistical_system as dpsys;

use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use dp::msg_structs::ComsAndShare;
use dp::hash_xor::*;
use blstrs::Scalar;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519Signature};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use bcs::{to_bytes, from_bytes};
use std::env;
use byteorder::{BigEndian, ReadBytesExt};

type SharedMap = Arc<RwLock<HashMap<u64, Vec<(Scalar, Scalar)>>>>;

const N_B: usize = 10;
// NUM_PROVERS >= 2*THRESHOLD + 1
const NUM_PROVERS: usize = 7;
const THRESHOLD: usize = 3;
const TYPES: usize = 3;

fn main() {
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
    let share_hashmap_clone = share_hashmap.clone();

    let mut key_file = File::open(format!("sk{}", ind)).unwrap();
    let mut bytes = Vec::new();
    key_file.read_to_end(&mut bytes).unwrap();
    let key: Ed25519PrivateKey = from_bytes(&bytes).unwrap();
    let mut boolvecvec_file = File::open(format!("boolvecvec{}", ind)).unwrap();
    let mut boolvecvec_bytes = Vec::new();
    boolvecvec_file.read_to_end(&mut boolvecvec_bytes).unwrap();
    let boolvecvec: Vec<Vec<bool>> = from_bytes(&boolvecvec_bytes).unwrap();

    // 读取并反序列化Scalarvecvec
    let mut Scalarvecvec_file = File::open(format!("Scalarvecvec{}", ind)).unwrap();
    let mut Scalarvecvec_bytes = Vec::new();
    Scalarvecvec_file.read_to_end(&mut Scalarvecvec_bytes).unwrap();
    let Scalarvecvec: Vec<Vec<Scalar>> = from_bytes(&Scalarvecvec_bytes).unwrap();

    let provers_vector = prover( key, boolvecvec, Scalarvecvec, ind);
    let provers_vec_clone = provers_vector.clone();

    let clients_handle = std::thread::spawn(move || {
        clients_connection(share_hashmap.clone(), provers_vector.clone(), PublicParameters::new(N_B, NUM_PROVERS, THRESHOLD, b"seed"), ind);
    });
    let verifier_handle = std::thread::spawn(move || {
        verifier_connection(share_hashmap_clone, provers_vec_clone, PublicParameters::new(N_B, NUM_PROVERS, THRESHOLD, b"seed"), ind);
    });

    clients_handle.join().unwrap();
    verifier_handle.join().unwrap();
}

// 实例化多个prover是为了模拟不同的类型疾病；开NUM_PROVERS个程序，一个程序模拟一个prover
fn prover(key: Ed25519PrivateKey, boolvecvec: Vec<Vec<bool>>, Scalarvecvec: Vec<Vec<Scalar>>, ind: usize) -> Vec<Prover> {
    // 生成公共参数
    let pp = PublicParameters::new(
        N_B, NUM_PROVERS, THRESHOLD, b"seed"
    );

    // 生成服务器实例
    let mut provers_vector: Vec<Prover> = Vec::new();  // 创建provers的实例
    for i in 0..TYPES {
        provers_vector.push(Prover::new(ind, boolvecvec[i].clone(), Scalarvecvec[i].clone(), &pp, key.clone()))
    }

    provers_vector
}

// 监听clients连接
fn clients_connection(share_hashmap: SharedMap, provervec: Vec<Prover>, pp: PublicParameters, ind: usize) {
    let addr = format!("127.0.0.1:{}", 8000 + ind);  // 这里改为提前定好的socket
    let listener = TcpListener::bind(&addr).unwrap();  // 每个prover监听不同的socket
    println!("Listening for clients on {}", addr);

    loop {
        let (socket, _) = listener.accept().unwrap();
        let hashmap_clone = share_hashmap.clone();
        let prover_clone = provervec[0].clone();
        let pp_clone = pp.clone();
        std::thread::spawn(move || {
            handle_client(socket, hashmap_clone, prover_clone, &pp_clone);
        });
    }
}

// 处理client连接
fn handle_client(mut socket: TcpStream, share_hashmap: SharedMap, prover: Prover, pp: &PublicParameters) {
    println!("Handling client");
    let mut com_and_share_vec: Vec<ComsAndShare> = Vec::new();
    for _ in 0..TYPES{
        let mut buffer = vec![0;665];
        let n=socket.read(&mut buffer).unwrap();
        //println!("len of buffer: {}", n);
        let com_and_share: ComsAndShare = from_bytes(&buffer).unwrap();  // com_and_share为接收到的ComsAndShare类型数据
        com_and_share_vec.push(com_and_share);
    }
    let id = com_and_share_vec[0].id;
    //println!("Received data from client {}", id);
    // Assuming verify_msg_and_sig function is defined and returns a boolean or some result
    // 做verify_msg_and_sig验证+签名
    let mut sharevec: Vec<(Scalar, Scalar)> = Vec::new();
    let mut sigs: Vec<Ed25519Signature> = Vec::new();
    for com_and_share in com_and_share_vec {
        let verification_result = prover.verify_msg_and_sig(&com_and_share, &pp);
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

    let mut hashmap = share_hashmap.write().unwrap();  // 获得写锁
    hashmap.insert(id, sharevec);  // 将sharevec插入hashmap
    println!("Inserted into hashmap");
    // 将签名返回clients
    for sig in &sigs {
        let response = to_bytes(sig).unwrap();
        //println!("len of response: {}", response.len());
        socket.write_all(&response).unwrap();
    }
}
// 监听verifier连接
fn verifier_connection(share_hashmap: SharedMap, provervec: Vec<Prover>, pp: PublicParameters, ind: usize) {
    let addr = format!("127.0.0.1:{}", 9000 + ind);  // 这里改为提前定好的socket
    let listener = TcpListener::bind(&addr).unwrap();
    println!("Listening for verifiers on {}", addr);

    loop {
        let (socket, _) = listener.accept().unwrap();
        let hashmap_clone = share_hashmap.clone();
        let provervec_clone = provervec.clone();
        let pp_clone = pp.clone();
        std::thread::spawn(move || {
            handle_verifier(socket, hashmap_clone, provervec_clone, &pp_clone);
        });
    }
}

fn handle_verifier(mut socket: TcpStream, share_hashmap: SharedMap, mut provervec: Vec<Prover>, pp: &PublicParameters) {
    let mut len_buf = [0; 8];
    if let Err(e) = socket.read_exact(&mut len_buf) {
        eprintln!("Failed to read length: {}", e);
        return;
    }

    let len = (&len_buf[..]).read_u64::<BigEndian>().unwrap() as usize;

    let mut buffer = vec![0; len];
    if let Err(e) = socket.read_exact(&mut buffer) {
        eprintln!("Failed to read message: {}", e);
        return;
    }

    let valid_ids: Vec<u64> = from_bytes(&buffer).unwrap();

    let hash = hash_T_to_bit_array(valid_ids.clone(), pp.get_n_b());
    for i in 0..provervec.len() {
        provervec[i].x_or(&pp, &hash);
    }

    let mut results: Vec<Vec<(Scalar, Scalar)>> = Vec::new();

    let hashmap = share_hashmap.read().unwrap();

    // 这里获取了value之后，应该还需要发送其他的数据
    for id in valid_ids {
        if let Some(value) = hashmap.get(&id) {
            results.push(value.clone());
        }
    }
    let results_type_id = transpose(&results);

    let mut output: Vec<(Scalar, Scalar)> = Vec::new();

    for i in 0..TYPES {
        output.push(provervec[i].calc_output_with_share(pp, results_type_id[i].clone()));
    }

    let response = to_bytes(&output).unwrap();
    socket.write_all(&response).unwrap();
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
