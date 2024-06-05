use aptos_crypto::hash;
use robust_verifiable_dp::commitment::Commit;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::vec;
use std::io::{self, Read, Write};
use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use std::sync::mpsc;
use robust_verifiable_dp::transcript::TranscriptEd;
use robust_verifiable_dp::public_parameters::PublicParameters;
use robust_verifiable_dp::hash_xor::{hash_T_to_bit_array, xor_commitments};
use robust_verifiable_dp::shamirlib::recon_u64;
use aptos_crypto::ed25519::Ed25519PublicKey;
use blstrs::{Scalar, G1Projective};
use group::Group;
use byteorder::{BigEndian, WriteBytesExt};

type SharedMap = Arc<RwLock<HashMap<u64, Vec<TranscriptEd>>>>;  // 用于线程切换

const N_B: usize = 10;
// NUM_PROVERS >= 2*THRESHOLD + 1
const NUM_PROVERS: usize = 7;
const THRESHOLD: usize = 3;
const TYPES: usize = 3;

const PROVER_ADDRESSES: [&str; 7] = [
    "127.0.0.1:9000",
    "127.0.0.1:9001",
    "127.0.0.1:9002",
    "127.0.0.1:9003",
    "127.0.0.1:9004",
    "127.0.0.1:9005",
    "127.0.0.1:9006",
];

fn main() {
    let hashmap: SharedMap = Arc::new(RwLock::new(HashMap::new()));  // 存放transcript的数据库(id, transcript, bool)
    let pp = PublicParameters::new(N_B, NUM_PROVERS, THRESHOLD, b"seed");

    // 反序列化pks
    let mut key_file = File::open("pks").unwrap();
    let mut bytes = Vec::new();
    key_file.read_to_end(&mut bytes).unwrap();
    let pks: Vec<Ed25519PublicKey> = bcs::from_bytes(&bytes).unwrap();

    // 反序列化comsvecvecvec
    let mut comsvecvecvec_file = File::open("comsvecvecvec").unwrap();
    let mut comsvecvecvec_bytes = Vec::new();
    comsvecvecvec_file.read_to_end(&mut comsvecvecvec_bytes).unwrap();
    let coms_prover_type_vec: Vec<Vec<Vec<G1Projective>>> = bcs::from_bytes(&comsvecvecvec_bytes).unwrap();

    let hashmap_clone = Arc::clone(&hashmap);
    let pp_clone = pp.clone();
    let pks_clone = pks.clone();

    // 启动客户端连接监听线程
    thread::spawn(move || {
        if let Err(e) = clients_connection(hashmap_clone, pp_clone, pks_clone) {
            eprintln!("Error in connection handler: {}", e);
        }
    });
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap(); // 等待用户按下回车键
    
        let map = hashmap.read().unwrap();
        let ids: Vec<u64> = map.keys().cloned().collect();
    
        //对用户的coms求和
        let mut coms_sum_t_p:Vec<Vec<G1Projective>>=vec![vec![G1Projective::identity();NUM_PROVERS];TYPES];
        for value in map.values() {
            for t in 0..TYPES{
                for p in 0..NUM_PROVERS{
                    coms_sum_t_p[t][p]+=value[t].coms()[p];
                }
            }
        }
    
        let mut share_proof_prover_type: Vec<Option<Vec<(Scalar, Scalar)>>> = Vec::new();
        let bytes = bcs::to_bytes(&ids).unwrap();
        let mut message = Vec::new();
        message.write_u64::<BigEndian>(bytes.len() as u64).unwrap();
        message.extend(bytes);
        
        for address in PROVER_ADDRESSES.iter() {
            match TcpStream::connect(address) {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(&message) {
                        // 写入操作失败
                        eprintln!("Failed to write to stream: {}", e);
                        continue;
                    }
                    let mut response = vec![0; 4096];
                    match stream.read(&mut response) {
                        Ok(size) => {
                            response.truncate(size);
    
                            match bcs::from_bytes::<Vec<(Scalar, Scalar)>>(&response) {
                                Ok(res) => {
                                    share_proof_prover_type.push(Some(res));
                                },
                                Err(e) => {
                                    eprintln!("Failed to deserialize response: {}", e);
                                    share_proof_prover_type.push(None);
                                },
                            }
                        },
                        Err(e) => {
                            eprintln!("Failed to read from stream: {}", e);
                            share_proof_prover_type.push(None);
                        },
                    }
                },
                Err(e) => {
                    eprintln!("Failed to connect: {}", e);
                    share_proof_prover_type.push(None);
                },
            }
        }
    
        let hash=hash_T_to_bit_array(ids, N_B);
    
        handle_responses(share_proof_prover_type,hash,coms_prover_type_vec.clone(),&pp,coms_sum_t_p.clone());
    }
}
fn clients_connection(hashmap: SharedMap, pp: PublicParameters, pks: Vec<Ed25519PublicKey>) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:10000")?;
    println!("Server listening on port 10000");

    for stream in listener.incoming() {
        match stream {
            Ok(socket) => {
                let hashmap_clone = Arc::clone(&hashmap);
                let pp = pp.clone();
                let pks = pks.clone();
                thread::spawn(move || {
                    handle_client(socket, hashmap_clone, pp, pks);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    Ok(())
}

fn handle_client(mut socket: TcpStream, hashmap: SharedMap, pp: PublicParameters, pks: Vec<Ed25519PublicKey>) {
    let mut buf = vec![0; 1115];
    let mut recv_data_vec = Vec::new();

    for _ in 0..TYPES {
        let n = match socket.read(&mut buf) {
            Ok(n) if n == 0 => {
                println!("Connection closed by client: {:?}", socket.peer_addr());
                return;
            }
            Ok(n) => n,
            Err(_) => {
                eprintln!("Failed to read data from socket");
                return;
            }
        };
        let recv_data: TranscriptEd = match bcs::from_bytes(&buf[..n]) {
            Ok(data) => data,
            Err(_) => {
                eprintln!("Failed to deserialize data");
                return;
            }
        };
        if recv_data.verify(&pp, &pks) {
            recv_data_vec.push(recv_data);
        }
    }
    let mut map = hashmap.write().unwrap();
    map.insert(recv_data_vec[0].id(), recv_data_vec.clone());

    let response = b"OK";
    if let Err(e) = socket.write_all(response) {
        eprintln!("Failed to write to socket: {}", e);
    }
}
fn handle_responses(
    share_proof_prover_type: Vec<Option<Vec<(Scalar, Scalar)>>>,
    hash: Vec<bool>,
    coms_prover_type_vec: Vec<Vec<Vec<G1Projective>>>,
    pp: &PublicParameters,
    coms_sum_t_p: Vec<Vec<G1Projective>>,
) {
    let mut valid: Vec<Vec<bool>> = vec![vec![false; NUM_PROVERS]; TYPES];

    for t in 0..TYPES {
        for p in 0..NUM_PROVERS {
            let coms_xor = xor_commitments(&coms_prover_type_vec[p][t], &hash, pp.get_g(), pp.get_h());
            let sum_coms_xor = coms_xor.iter().fold(G1Projective::identity(), |acc, &x| acc + x);
            let output_p = share_proof_prover_type[p].clone();
            if let Some(output) = output_p {
                let (share, proof) = output[t];
                if pp.get_commit_base().commit(share, proof) == sum_coms_xor + coms_sum_t_p[t][p] {
                    valid[t][p] = true;
                }
            }
        }
        let mut count = 0;
        let mut valid_share: Vec<Scalar> = Vec::new();
        let mut xs: Vec<u64> = Vec::new();
        for p in 0..NUM_PROVERS {
            if valid[t][p] {
                count += 1;
                valid_share.push(share_proof_prover_type[p].clone().unwrap()[t].0);
                xs.push((p + 1) as u64);
            }
            if count > pp.get_threshold() {
                break;
            }
        }
        let x = recon_u64(&valid_share.as_slice(), &xs.as_slice());
        let str = x.to_string();
        println!("{}", str);
    }
}

fn transpose(input: Vec<Option<Vec<(Scalar, Scalar)>>>) -> Vec<Vec<Option<(Scalar, Scalar)>>> {
    let max_len = input.iter().filter_map(|v| v.as_ref()).map(|v| v.len()).max().unwrap_or(0);
    let mut output: Vec<Vec<Option<(Scalar, Scalar)>>> = vec![vec![None; input.len()]; max_len];

    for (i, opt_vec) in input.into_iter().enumerate() {
        if let Some(vec) = opt_vec {
            for (j, val) in vec.into_iter().enumerate() {
                output[j][i] = Some(val);
            }
        }
    }

    output
}
