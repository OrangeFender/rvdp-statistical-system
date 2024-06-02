// ================================test: v6=====================================
// 删除了SharedReceiver，我们只需要利用读写锁来完成即可
// 锁：在 Rust 和 Tokio 中，锁的获取和释放是由范围（scope）自动管理的。锁的释放是隐式的，当锁的作用域结束时（即超出它的使用范围），锁就会自动释放。
// 这是因为 Rust 的所有权系统和自动资源管理（RAII，Resource Acquisition Is Initialization）机制。
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

// Test换成transcript
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Test {
    pub id: u64,
    pub s: String,
}

type SharedMap = Arc<RwLock<HashMap<u64, Test>>>;  // 用于线程切换
const NUM_PROVER: i32 = 5;  // Prover的数量

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hashmap: SharedMap = Arc::new(RwLock::new(HashMap::new()));  // 存放transcript的数据库(id, transcript, bool)

    // 创建用于线程间通信的通道
    let (tx, rx) = mpsc::channel(100);

    // 启动异步任务处理监听Clients连接并写入hashmap
    // tokio::spawn启动一个新的异步任务(一个异步函数)。这个新任务会在后台异步运行，不会阻塞当前线程。
    // 使用 tokio::spawn 可以方便地并发执行多个异步任务。Tokio 运行时会自动调度这些任务，使它们高效地共享线程资源。
    let hashmap_clone = Arc::clone(&hashmap);
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        if let Err(e) = clients_connection(hashmap_clone, tx_clone).await {
            eprintln!("Error in connection handler: {}", e);
        }
    });

    loop {
        // ===================================================================
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
        // ===================================================================

        // 打印其他功能
        println!("You can do other functions");
        println!("=======================finish====================");

        // 连接指定地址并发送hashmap中的内容
        let hashmap_clone = Arc::clone(&hashmap);
        tokio::spawn(async move {
            if let Err(e) = connect_and_send("127.0.0.1:7878", hashmap_clone).await {
                eprintln!("Error in sender: {}", e);
            }
        }).await.expect("Failed to execute connect_and_send");

        // 接收远程地址的数据
        let received_data = receive_data("127.0.0.1:7878").await?;  // 返回一个Test类型的向量，这个后面可以再修改具体是什么
        for data in received_data {
            println!("Received data: {:?}", data);
        }

        // 其他的验证
        println!("You can do verification.");

        println!("=====================差分隐私结果为：======================");

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

async fn clients_connection(hashmap: SharedMap, tx: mpsc::Sender<SharedMap>) -> Result<(), Box<dyn std::error::Error>> {
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
        let n = match socket.read(&mut buf).await {  // 从 socket 中读取数据，数据会存储在 buf 中
            // 当读取操作成功 (Ok) 并且读取的字节数为 0 (n == 0) 时，表示客户端已经关闭了连接。
            // 将共享的 hashmap 发送给发送线程。通过 tx.send(Arc::clone(&hashmap)).await 发送。返回 return，结束当前任务。
            Ok(n) if n == 0 => {  
                println!("Connection closed by client: {:?}", socket.peer_addr());
                // 发送共享的hashmap给发送线程
                let _ = tx.send(Arc::clone(&hashmap)).await;
                return;
            }
            Ok(n) => n,  // 当读取操作成功 (Ok) 并且读取的字节数不为 0 (n > 0) 时，返回读取的字节数 n，继续处理读取的数据。
            Err(_) => {  // 当读取操作失败 (Err) 时，打印错误日志，并返回 return，结束当前任务。
                eprintln!("Failed to read data from socket");
                return;
            }
        };

        // 反序列化，如果成功则将反序列化得到的 Test 对象赋值给 recv_data。
        let recv_data: Test = match bcs::from_bytes(&buf[..n]) {
            Ok(data) => data,
            Err(_) => {
                eprintln!("Failed to deserialize data");
                return;
            }
        };
        println!("Received data: {:?}", recv_data);

        // 将反序列化得到的 Test 对象插入到共享的 hashmap 中：
        let mut map = hashmap.write().await;  // 获得读锁
        map.insert(recv_data.id, recv_data.clone());
        println!("The contents of hash map: {:?}", map);
    }
}

async fn connect_and_send(addr: &str, hashmap: SharedMap) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..NUM_PROVER {
        // 创建连接
        let mut stream = TcpStream::connect(addr).await?;
        println!("Connected to {}", addr);

        // 读取hashmap内容并发送
        let map = hashmap.read().await;  // 获得读锁
        for (id, test) in map.iter() {
            let data = bcs::to_bytes(&test).expect("Failed to serialize data");
            stream.write_all(&data).await?;
            println!("Sent data: {:?}", test);
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await; // 等待一段时间后再次发送
    }
    Ok(())
}

async fn receive_data(addr: &str) -> Result<Vec<Test>, Box<dyn std::error::Error>> {
    let mut received_data = Vec::new();
    let mut stream = TcpStream::connect(addr).await?;
    println!("Connected to {} for receiving data", addr);

    for _ in 0..NUM_PROVER {
        let mut buf = vec![0; 1024];
        let n = stream.read(&mut buf).await?;
        let data: Test = bcs::from_bytes(&buf[..n]).expect("Failed to deserialize received data");
        received_data.push(data);
    }

    Ok(received_data)
}