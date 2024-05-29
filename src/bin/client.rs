extern crate robust_verifiable_dp as dp;
extern crate rvdp_statistical_system as dpsys;

use dp::public_parameters::PublicParameters;
use dp::client::Client;
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use dpsys::shared::structs::{Config, SocketAddresses};




pub fn client(conf_str:&str,address:&str,inputs:Vec<bool> ,id:usize){



    let mut pp:PublicParameters;
    let types:usize;
    //从json中生成公共参数
    match serde_json::from_str::<Config>(conf_str) {
        Ok(c) => {
             pp = PublicParameters::new(
                c.n_b, c.num_provers, c.threshold, c.seed.as_bytes()
                );
            types = c.types;
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
    let mut client_type:Vec<Client> = Vec::new();
    for i in 0..types {
        client_type.push(Client::new(id, inputs[i], &pp, ));
    }

    //发送commitments
    
    
    
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