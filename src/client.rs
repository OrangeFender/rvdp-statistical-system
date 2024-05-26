extern crate robust_verifiable_dp as dp;

use dp::public_parameters::PublicParameters;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct Config{
    pub types: usize,
    pub n_b: usize,
    pub num_provers: usize,
    pub threshold: usize,
    pub seed: String,
}

struct SocketAddresses {
    addresses: Vec<String>,
}


pub fn client(imputs:Vec<bool> ){
    // Create public parameters
    let conf_str=r#"
    {
        “types":15,
        "n_b": 10,
        "num_provers": 10,
        "threshold": 4,
        "seed": "seed1001",
    }
"#;

let addres = r#"
{
    "ip_addresses": [
        "192.168.0.1:1234",
        "192.168.0.2:1234",
        "10.0.0.1:1234",
        "172.16.0.1:1234"
    ]
}
"#;

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

    
}

