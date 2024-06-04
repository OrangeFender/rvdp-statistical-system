use aptos_crypto::hash;
use robust_verifiable_dp::commitment::Commit;
// ================================test: v6=====================================
// 删除了SharedReceiver，我们只需要利用读写锁来完成即可
// 锁：在 Rust 和 Tokio 中，锁的获取和释放是由范围（scope）自动管理的。锁的释放是隐式的，当锁的作用域结束时（即超出它的使用范围），锁就会自动释放。
// 这是因为 Rust 的所有权系统和自动资源管理（RAII，Resource Acquisition Is Initialization）机制。
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::vec;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{timeout, Duration};
use robust_verifiable_dp::transcript::TranscriptEd;
use robust_verifiable_dp::public_parameters::PublicParameters;
use robust_verifiable_dp::hash_xor::{hash_T_to_bit_array,xor_commitments};
use robust_verifiable_dp::shamirlib::recon_u64;
use aptos_crypto::ed25519::Ed25519PublicKey;
use std::io::{self, Write};
use blstrs::{Scalar,G1Projective};
use group::Group;
use std::fs::File;
use std::io::Read;

type SharedMap = Arc<RwLock<HashMap<u64, Vec<TranscriptEd>>>>;  // 用于线程切换


const N_B: usize = 10;
// NUM_PROVERS >= 2*THRESHOLD + 1
const NUM_PROVERS: usize = 7;
const THRESHOLD: usize = 3;
const TYPES: usize = 3;

const PROVER_ADDRESSES: [&str; 7] = [
    "127.0.0.1:8001",
    "127.0.0.1:8002",
    "127.0.0.1:8003",
    "127.0.0.1:8004",
    "127.0.0.1:8005",
    "127.0.0.1:8006",
    "127.0.0.1:8007",
];

#[tokio::main]
async fn main()  {
    let hashmap: SharedMap = Arc::new(RwLock::new(HashMap::new()));  // 存放transcript的数据库(id, transcript, bool)

    let pp = PublicParameters::new(
        N_B, NUM_PROVERS, THRESHOLD, b"seed"
    );

    let another_pp = pp.clone();

    //反序列化pks
    let mut key_file = File::open(format!("pks")).unwrap();
    let mut bytes = Vec::new();
    key_file.read_to_end(&mut bytes).unwrap();
    let pks:Vec<Ed25519PublicKey> = bcs::from_bytes(&bytes).unwrap();

    //反序列化comsvecvecvec
    let mut comsvecvecvec_file = File::open(format!("comsvecvecvec")).unwrap();
    let mut comsvecvecvec_bytes = Vec::new();
    comsvecvecvec_file.read_to_end(&mut comsvecvecvec_bytes).unwrap();
    let coms_prover_type_vec: Vec<Vec<Vec<G1Projective>>> = bcs::from_bytes(&comsvecvecvec_bytes).unwrap();

    // 创建用于线程间通信的通道
    // 启动异步任务处理监听Clients连接并写入hashmap
    // tokio::spawn启动一个新的异步任务(一个异步函数)。这个新任务会在后台异步运行，不会阻塞当前线程。
    // 使用 tokio::spawn 可以方便地并发执行多个异步任务。Tokio 运行时会自动调度这些任务，使它们高效地共享线程资源。
    let hashmap_clone = Arc::clone(&hashmap);
    tokio::spawn(async move {
        if let Err(e) = clients_connection(hashmap_clone,pp.clone(),pks).await {
            eprintln!("Error in connection handler: {}", e);
        }
    });
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap(); // 等待用户按下回车键

    
        let map = hashmap.read().await;
        let ids: Vec<u64> = map.keys().cloned().collect();
        
        //对用户的coms求和
        let mut coms_sum_t_p:Vec<Vec<G1Projective>>=vec![vec![G1Projective::identity();TYPES];NUM_PROVERS];
        for value in map.values() {
            for t in 0..TYPES{
                for p in 0..NUM_PROVERS{
                    coms_sum_t_p[t][p]+=value[t].coms()[p];
                }
            }
        }
        

        let mut share_proof_prover_type: Vec<Option<Vec<(Scalar, Scalar)>>> = Vec::new();
    
        
        for address in PROVER_ADDRESSES.iter() {
            let connect_future = TcpStream::connect(address);
            let result = timeout(Duration::from_secs(5), connect_future).await; // 设置超时时间为5秒
            
            match result {
                Ok(Ok(mut stream)) => {
                    if let Err(e) = timeout(Duration::from_secs(5), stream.write_all(&bytes)).await {
                        // 写入操作超时或失败
                        eprintln!("Failed to write to stream: {}", e);
                        continue;
                    }
            
                    let mut response = vec![0; 4096];
                    let read_result = timeout(Duration::from_secs(5), stream.read(&mut response)).await;
            
                    match read_result {
                        Ok(Ok(size)) => {
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
                        Ok(Err(e)) => {
                            eprintln!("Failed to read from stream: {}", e);
                            share_proof_prover_type.push(None);
                        },
                        Err(_) => {
                            eprintln!("Read from stream timed out");
                            share_proof_prover_type.push(None);
                        },
                    }
                },
                Ok(Err(e)) => {
                    eprintln!("Failed to connect: {}", e);
                    share_proof_prover_type.push(None);
                },
                Err(_) => {
                    eprintln!("Connection timed out");
                    share_proof_prover_type.push(None);
                },
            }
        }

        let hash=hash_T_to_bit_array(ids, N_B);
    
        handle_responses(share_proof_prover_type,hash,coms_prover_type_vec.clone(),&another_pp,coms_sum_t_p.clone());
    }
    
}

async fn clients_connection(hashmap: SharedMap,pp:PublicParameters,pks:Vec<Ed25519PublicKey>) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on port 8080");
    
    loop {
        let pks=pks.clone();
        let pp=pp.clone();
        let (socket, _) = listener.accept().await?;
        println!("New connection: {:?}", socket.peer_addr());

        let hashmap_clone = Arc::clone(&hashmap);

        tokio::spawn(async move {
            handle_client(socket, hashmap_clone,pp,pks).await;
        });
    }
}

async fn handle_client(mut socket: TcpStream, hashmap: SharedMap,pp:PublicParameters,pks:Vec<Ed25519PublicKey>) {
    let mut buf = vec![0; 4096];

    loop {
        let n = match socket.read(&mut buf).await {  // 从 socket 中读取数据，数据会存储在 buf 中
            // 当读取操作成功 (Ok) 并且读取的字节数为 0 (n == 0) 时，表示客户端已经关闭了连接。
            // 将共享的 hashmap 发送给发送线程。通过 tx.send(Arc::clone(&hashmap)).await 发送。返回 return，结束当前任务。
            Ok(n) if n == 0 => {  
                println!("Connection closed by client: {:?}", socket.peer_addr());
                return;
            }
            Ok(n) => n,  // 当读取操作成功 (Ok) 并且读取的字节数不为 0 (n > 0) 时，返回读取的字节数 n，继续处理读取的数据。
            Err(_) => {  // 当读取操作失败 (Err) 时，打印错误日志，并返回 return，结束当前任务。
                eprintln!("Failed to read data from socket");
                return;
            }
        };

        // 反序列化，如果成功则将反序列化得到的 Test 对象赋值给 recv_data。
        let recv_data: Vec<TranscriptEd> = match bcs::from_bytes(&buf[..n]) {
            Ok(data) => data,
            Err(_) => {
                eprintln!("Failed to deserialize data");
                return;
            }
        };

        if recv_data.iter().all(|item| item.verify(&pp, &pks)) {
            // 将反序列化得到的 Test 对象插入到共享的 hashmap 中：
            let mut map = hashmap.write().await;  // 获得读锁
            map.insert(recv_data[0].id(), recv_data.clone());
            //向用户回复"OK"
            let response = b"OK";
            if let Err(e) = socket.write_all(response).await {
                eprintln!("Failed to write to socket: {}", e);
            }
        }
    }
}

fn handle_responses(share_proof_prover_type: Vec<Option<Vec<(Scalar, Scalar)>>>,hash:Vec<bool>,coms_prover_type_vec:Vec<Vec<Vec<G1Projective>>>,pp:&PublicParameters,coms_sum_t_p:Vec<Vec<G1Projective>>) {
    //let share_proof_type_prover = transpose(share_proof_prover_type);
    let mut valid: Vec<Vec<bool>> = vec![vec![false; NUM_PROVERS]; TYPES];

    for t in 0..TYPES{
        for p in 0..NUM_PROVERS{
            let coms_xor=xor_commitments(&coms_prover_type_vec[p][t], &hash, pp.get_g(), pp.get_h());
            let sum_coms_xor=coms_xor.iter().fold(G1Projective::identity(), |acc, &x| acc + x);
            let output_p=share_proof_prover_type[p].clone();
            if let Some(output)=output_p{
                let (share,proof)=output[t];
                if pp.get_commit_base().commit(share, proof)==sum_coms_xor+coms_sum_t_p[t][p]{
                    valid[t][p]=true;
                }
            }
        }
        let mut count=0;
        let mut valid_share:Vec<Scalar>=Vec::new();
        let mut xs:Vec<u64>=Vec::new();
        for p in 0..NUM_PROVERS{
            if valid[t][p]{
                count+=1;
                valid_share.push(share_proof_prover_type[p].clone().unwrap()[t].0);
                xs.push((p+1) as u64);
            }
            if count>pp.get_threshold(){
                break;
            }
        }
        let x=recon_u64(&&valid_share.as_slice(), &xs.as_slice());
        let str=x.to_string();
        println!("{}",str);

    }
}

fn transpose(input: Vec<Option<Vec<(Scalar, Scalar)>>>) -> Vec<Vec<Option<(Scalar, Scalar)>>> {
    // Find the maximum length of the inner vectors
    let max_len = input.iter().filter_map(|v| v.as_ref()).map(|v| v.len()).max().unwrap_or(0);

    // Create a new vector with `max_len` vectors
    let mut output: Vec<Vec<Option<(Scalar, Scalar)>>> = vec![vec![None; input.len()]; max_len];

    // Iterate over the input vector and add the elements to the new vector
    for (i, opt_vec) in input.into_iter().enumerate() {
        if let Some(vec) = opt_vec {
            for (j, val) in vec.into_iter().enumerate() {
                output[j][i] = Some(val);
            }
        }
    }

    output
}