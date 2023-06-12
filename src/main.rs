use std::env;
use std::process;

fn main() {
    // collect the passed in arguments
    let args: Vec<String> = env::args().collect();

    // build our config based on the config layed out in the library
    let config = json_parser::Config::build(&args).unwrap_or_else(|err| {
        println!("There was a problem parsing the arguments: {err}");
        process::exit(1)
    });

    // if there's an error running the runner, print the error and exit 
    if let Err(e) = json_parser::run(config) {
        println!("Application error: {e}");
        process::exit(1)
    }

    /*let json: serde_json::Value =
        serde_json::from_str(the_file).expect("JSON was not well-formatted");

    println!("{}", json["potentialAction"][0]["actions"].len())*/
}