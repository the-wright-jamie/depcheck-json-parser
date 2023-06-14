use std::{process};

use clap::Parser;

fn main() {
    let args = depcheck_json_parser::Config::parse();

    if let Err(e) = depcheck_json_parser::run(args) {
        println!("Error: {}", e.to_string());
        println!("Use the -h (or --help) option to see usage.");

        process::exit(1)
    }
}