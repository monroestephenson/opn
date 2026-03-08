#![allow(dead_code)]

#[path = "../cli.rs"]
mod cli;
#[path = "../model.rs"]
mod model;

use clap::CommandFactory;
use std::fs;

fn main() -> anyhow::Result<()> {
    let cmd = cli::Cli::command();
    let man = clap_mangen::Man::new(cmd.clone());

    fs::create_dir_all("man")?;
    let mut out = Vec::new();
    man.render(&mut out)?;
    fs::write("man/opn.1", out)?;

    println!("Generated man/opn.1 for {}", cmd.get_name());
    Ok(())
}
