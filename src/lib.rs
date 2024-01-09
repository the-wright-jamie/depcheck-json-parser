use std::{error::Error, fs::File, io::Read};

use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Struct for the config
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Config {
    /// The path to the OWASP Dependency Checker JSON report
    scan_results_path: String,

    /// List the vulnerable dependencies from the report
    #[arg(short, long)]
    list_vulnerable_dependencies: bool,

    /// List details regarding CVEs on vulnerability
    #[arg(short, long)]
    details: bool,

    /// Print colorless
    #[arg(short, long)]
    no_color: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportJson {
    report_schema: String,
    scan_info: ScanInfo,
    project_info: ProjectInfo,
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanInfo {
    engine_version: String,
    data_source: Vec<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectInfo {
    name: String,
    #[serde(rename = "groupID")]
    group_id: Option<String>,
    #[serde(rename = "artifactID")]
    artifact_id: Option<String>,
    version: Option<String>,
    report_date: String,
    credits: Credits,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct Credits {
    nvd: String,
    cisa: String,
    npm: String,
    retirejs: String,
    ossindex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Dependency {
    is_virtual: bool,
    file_name: String,
    file_path: String,
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    project_references: Option<Vec<Value>>,
    included_by: Option<Vec<IncludedBy>>,
    evidence_collected: EvidenceCollected,
    packages: Option<Vec<Value>>,
    vulnerability_ids: Option<Vec<VulnerabilityId>>,
    vulnerabilities: Option<Vec<Vulnerability>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct IncludedBy {
    reference: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceCollected {
    vendor_evidence: Vec<Value>,
    product_evidence: Vec<Value>,
    version_evidence: Vec<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VulnerabilityId {
    id: String,
    confidence: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Vulnerability {
    source: String,
    name: String,
    severity: String,
    cvssv2: Option<CVSSV2>,
    cwes: Vec<Value>,
    description: String,
    notes: String,
    references: Vec<Value>,
    vulnerable_software: Vec<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CVSSV2 {
    score: f32,
    access_vector: String,
    access_complexity: String,
    authenticationr: String,
    confidential_impact: Option<String>,
    integrity_impact: String,
    availability_impact: String,
    severity: String,
}

static mut RED: &str = "\x1b[1;31m";
static mut BOLD: &str = "\x1b[1m";
static mut YELLOW: &str = "\x1b[93m";
static mut RESET: &str = "\x1b[0m";
static mut UNDERLINE: &str = "\x1b[4m";

struct ProcessingResults {
    project_name: String,
    found_vulnerabilities: usize,
    vulnerable_dependencies: usize,
    dependencies: Vec<String>,
}

fn parse_json(file_path: &str) -> Result<ReportJson, Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let json_value: Value = serde_json::from_str(&contents)?;
    let report_json: ReportJson = serde_json::from_value(json_value).expect("msg");

    return Ok(report_json);
}

fn set_colors() {
    if Config::parse().no_color {
        unsafe {
            RED = "";
            BOLD = "";
            YELLOW = "";
            RESET = "";
            UNDERLINE = "";
        }
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    set_colors();

    let results = match parse_json(&config.scan_results_path) {
        Ok(raw_json) => process_json(&raw_json),
        Err(err) => {
            return Err(err);
        }
    };

    if results.vulnerable_dependencies > 0 {
        unsafe {
            if results.project_name.is_empty() {
                println!("{RED}Vulnerable dependencies found{RESET}");
            } else {
                println!(
                    "{RED}Vulnerable dependencies found in {BOLD}{0}{RESET}",
                    results.project_name
                );
            }
            println!(
                "{RED}{0}{RESET} {BOLD}vulnerable dependencies{RESET}",
                results.vulnerable_dependencies
            );
            println!(
                "{RED}{0}{RESET} {BOLD}total vulnerabilities{RESET}",
                results.found_vulnerabilities
            );
        }
        if config.list_vulnerable_dependencies {
            unsafe {
                println!("\n{BOLD}{UNDERLINE}Vulnerable Dependencies List{RESET}");
            }
            results
                .dependencies
                .iter()
                .for_each(|dependency| println!("{0}", dependency))
        }
        if config.details {
            unsafe {
                println!("\n{BOLD}{UNDERLINE}Vulnerability Details{RESET}");
            }
            match parse_json(&config.scan_results_path) {
                Ok(raw_json) => print_cves(&raw_json),
                Err(err) => {
                    return Err(err);
                }
            };
        }
    } else {
        println!("🎉 All clear!")
    }

    Ok(())
}

fn get_dependencies_from_json(json_to_process: &ReportJson) -> &Vec<Dependency> {
    &json_to_process.dependencies
}

fn process_json(json_to_process: &ReportJson) -> ProcessingResults {
    let mut total_vulnerabilities = 0;
    let mut vulnerable_dependencies = 0;
    let mut deps: Vec<String> = Vec::new();

    let dependencies = get_dependencies_from_json(json_to_process);

    let longest_name = find_longest_name(dependencies);

    for dependency in dependencies {
        for vulnerabilities in &dependency.vulnerabilities {
            total_vulnerabilities += vulnerabilities.len();
            vulnerable_dependencies += 1;
            if let Some(included_by) = &dependency.included_by {
                let spaces = produce_spacing(&longest_name, &dependency.file_name);
                unsafe {
                    deps.push(format!(
                        "{YELLOW}{0}{RESET}{1} from {BOLD}{2}{RESET}",
                        dependency.file_name, spaces, included_by[0].reference
                    ))
                }
            } else {
                deps.push(dependency.file_name.clone())
            }
        }
    }

    ProcessingResults {
        project_name: json_to_process.project_info.name.clone(),
        found_vulnerabilities: total_vulnerabilities,
        vulnerable_dependencies,
        dependencies: deps,
    }
}

fn print_cves(json_to_process: &ReportJson) {
    let dependencies = get_dependencies_from_json(json_to_process);

    let longest_name = find_longest_name(dependencies);

    for dependency in dependencies {
        for vulnerabilities in &dependency.vulnerabilities {
            if let Some(included_by) = &dependency.included_by {
                let spaces = produce_spacing(&longest_name, &dependency.file_name);
                unsafe {
                    println!(
                        "{UNDERLINE}{YELLOW}{0}{RESET}{spaces} from {BOLD}{1}{RESET}",
                        dependency.file_name, included_by[0].reference
                    );
                }
            } else {
                unsafe {
                    println!("\n{UNDERLINE}{YELLOW}{0}{RESET}", dependency.file_name);
                }
            }
            for vulnerability in vulnerabilities {
                unsafe {
                    println!(
                        "{RED}{0}{RESET}: {1}\n",
                        vulnerability.name, vulnerability.description
                    );
                }
            }
        }
    }
}

fn find_longest_name(dependencies: &Vec<Dependency>) -> usize {
    let mut longest_name = 0;

    for dependency in dependencies {
        if let Some(_vulnerabilities) = &dependency.vulnerabilities {
            if dependency.file_name.len() > longest_name {
                longest_name = dependency.file_name.len();
            }
        }
    }

    longest_name
}

fn produce_spacing(longest_name: &usize, current_name: &str) -> String {
    let how_many_spaces = longest_name - current_name.len();
    let mut spaces = String::from("");

    for _i in 0..how_many_spaces {
        spaces.push(' ');
    }

    spaces
}
