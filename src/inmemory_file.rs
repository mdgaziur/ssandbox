use memfd::{Memfd, MemfdOptions};

pub fn new_inmemory_file(filename: &str) -> anyhow::Result<Memfd> {
    Ok(MemfdOptions::default().create(filename)?)
}
