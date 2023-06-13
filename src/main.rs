use std::process;

use clap::Parser;

fn main() {
    // collect the passed in arguments
    let args = depcheck_json_parser::Config::parse();

    // if there's an error running the runner, print the error and exit 
    if let Err(e) = depcheck_json_parser::run(args) {
        println!("Error: {}", e.to_string());
        println!("Use the -h (or --help) option to see usage.");

        process::exit(1)
    }

    /*let json: serde_json::Value =
        serde_json::from_str(the_file).expect("JSON was not well-formatted");

    println!("{}", json["potentialAction"][0]["actions"].len())*/
}