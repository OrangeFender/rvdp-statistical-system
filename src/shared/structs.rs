use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config{
    pub types: usize,
    pub n_b: usize,
    pub num_provers: usize,
    pub threshold: usize,
    pub seed: String,
}
#[derive(Serialize, Deserialize, Debug)]

pub struct SocketAddresses {
    addresses: Vec<String>,
}

