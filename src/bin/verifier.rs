// 用读写锁完成线程之间的切换
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Test {
    pub id: u64,
    pub s: String,
}

type SharedMap = Arc<RwLock<HashMap<u64, Test>>>;
type SharedReceiver = Arc<Mutex<mpsc::Receiver<SharedMap>>>;
const NUM_PROVER: i32 = 5;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hashmap: SharedMap = Arc::new(RwLock::new(HashMap::new()));

    // 创建用于线程间通信的通道
    let (tx, rx) = mpsc::channel(100);
    let shared_rx = Arc::new(Mutex::new(rx));

    // 启动线程处理监听连接并写入hashmap
    let hashmap_clone = Arc::clone(&hashmap);
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_connections(hashmap_clone, tx_clone).await {
            eprintln!("Error in connection handler: {}", e);
        }
    });

    loop {
        // 创建一个异步任务来等待用户输入
        let input_task = tokio::spawn(async {
            let stdin = tokio::io::stdin();
            let mut reader = BufReader::new(stdin);
            let mut lines = reader.lines();

            // 等待用户按下回车键
            println!("Press Enter to continue...");
            lines.next_line().await.expect("Failed to read line");
        });

        // 等待用户按下回车键
        input_task.await.expect("Failed to wait for input");

        // 打印其他功能
        println!("You can do other functions");
        println!("=======================finish====================");

        // 连接指定地址并发送hashmap中的内容
        let hashmap_clone = Arc::clone(&hashmap);
        let shared_rx_clone = Arc::clone(&shared_rx);
        tokio::spawn(async move {
            if let Err(e) = connect_and_send("127.0.0.1:7878", hashmap_clone, shared_rx_clone).await {
                eprintln!("Error in sender: {}", e);
            }
        }).await.expect("Failed to execute connect_and_send");

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

async fn handle_connections(hashmap: SharedMap, tx: mpsc::Sender<SharedMap>) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on port 8080");

    loop {
        let (socket, _) = listener.accept().await?;
        println!("New connection: {:?}", socket.peer_addr());

        let hashmap_clone = Arc::clone(&hashmap);
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            handle_client(socket, hashmap_clone, tx_clone).await;
        });
    }
}

async fn handle_client(mut socket: TcpStream, hashmap: SharedMap, tx: mpsc::Sender<SharedMap>) {
    let mut buf = vec![0; 1024];

    loop {
        let n = match socket.read(&mut buf).await {
            Ok(n) if n == 0 => {
                println!("Connection closed by client: {:?}", socket.peer_addr());
                // 处理完hashmap中的数据
                process_hashmap(&hashmap).await;
                // 发送共享的hashmap给发送线程
                let _ = tx.send(Arc::clone(&hashmap)).await;
                return;
            }
            Ok(n) => n,
            Err(_) => {
                eprintln!("Failed to read data from socket");
                return;
            }
        };

        let recv_data: Test = match bcs::from_bytes(&buf[..n]) {
            Ok(data) => data,
            Err(_) => {
                eprintln!("Failed to deserialize data");
                return;
            }
        };
        println!("Received data: {:?}", recv_data);

        let mut map = hashmap.write().await;  // 获得读锁
        map.insert(recv_data.id, recv_data.clone());
        println!("The contents of hash map: {:?}", map);
    }
}

async fn process_hashmap(hashmap: &SharedMap) {
    // let map = hashmap.read().await;
    // 在这里实现处理hashmap的逻辑
    // println!("Processing hashmap data: {:?}", map);
    println!("Processing hashmap data.");
    // 处理完后可以清空hashmap或者进行其他操作
}

async fn connect_and_send(addr: &str, hashmap: SharedMap, shared_rx: SharedReceiver) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..NUM_PROVER {
        // 接收更新后的hashmap
        let hashmap = {
            let mut rx = shared_rx.lock().await;
            rx.recv().await.expect("Failed to receive hashmap")
        };

        // 创建连接
        let mut stream = TcpStream::connect(addr).await?;
        println!("Connected to {}", addr);

        // 读取hashmap内容并发送
        let map = hashmap.read().await;  // 获得写锁
        for (id, test) in map.iter() {
            let data = bcs::to_bytes(&test).expect("Failed to serialize data");
            stream.write_all(&data).await?;
            println!("Sent data: {:?}", test);
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await; // 等待一段时间后再次发送
    }
    Ok(())
}