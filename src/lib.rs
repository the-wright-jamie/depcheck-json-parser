use std::error::Error;
use std::{fs, env};

pub struct Config {
    pub query: String,
    pub file_path: String,
    pub ignore_case: bool,
}

impl Config {
    pub fn build(args: &[String]) -> Result<Config, &'static str> {
        if args.len() < 3 {
            return Err("Not enough arguments");
        }
        let query = args[1].clone();
        let file_path = args[2].clone();

        let ignore_case = env::var("IGNORE_CASE").is_ok();

        Ok(Config { query, file_path, ignore_case })
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(config.file_path)?;

    let results = if config.ignore_case {
        case_insensitive_search(&config.query, &contents)
    } else {
        case_sensitive_search(&config.query, &contents)
    }

    for line in results {
        println!("{line}");
    }

    Ok(())
}

fn case_sensitive_search<'a>(query: &str, contents: &'a str) -> Vec<&'a str> {
    contents
        .lines()
        .filter(|line| line.contains(query))
        .collect()
}

fn case_insensitive_search<'a>(query: &str, contents: &'a str) -> Vec<&'a str> {
    let query = query.to_lowercase();

    println!("{query}");

    contents
        .lines()
        .filter(|line| line.to_lowercase().contains(&query))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_sensitive() {
        let query = "duc";
        let contents = "\
Rust:
safe, fast, productive.
Pick three.
Duck tape 😛";

        assert_eq!(vec!["safe, fast, productive."], case_sensitive_search(query, contents));
    }

    #[test]
    fn case_insensitive() {
        let query = "rUsT"; //🫨
        let contents = "\
Rust:
safe, fast, productive.
Pick three.
Trust me 😛";

        assert_eq!(vec!["Rust:", "Trust me 😛"], case_insensitive_search(query, contents));
    }
}