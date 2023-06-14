use std::{error::Error, fs::File, io::{Read, self, Write}, env};

use serde::{Deserialize, Serialize};
use clap::Parser;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Config {
    /// The path to the OWASP Dependency Checker JSON report
    scan_results_path: String,

    /// What file name to use for the report
    #[arg(short, long, default_value = "processed_report.txt")]
    report_file_name: String,

    /// Bypass overwrite protection
    #[arg(short, long)]
    force_overwrite: bool,

    /// Generates and a saves a machine readable report for later processing.
    /// If not present, will just print results to terminal.
    #[arg(short, long)]
    generate_report: bool,

    /// Count the total found vulnerabilities
    #[arg(short, long)]
    count_vulnerabilities: bool,

    /// List the vulnerable dependencies from the report
    #[arg(short, long)]
    list_vulnerable_dependencies: bool,
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
    data_source: Vec<Value>
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectInfo {
    name: String,
    #[serde(rename = "groupID")]
    group_id: String,
    #[serde(rename = "artifactID")]
    artifact_id: String,
    version: String,
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
    project_references: Vec<Value>,
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
    confidential_impact: String,
    integrity_impact: String,
    availability_impact: String,
    severity: String,
}

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

    return Ok(report_json)
}

fn directory_check(report_file_name: &str) {
    if let Ok(current_dir) = env::current_dir() {
        let file_path = current_dir.join(report_file_name);
        if file_path.exists() && file_path.is_file() {
            println!("'{0}' exists in the current directory. It will be overwritten by this command. If you are ok with this then", report_file_name);
            press_any_key();
        }
    } else {
        println!("Overwrite protection check failed. Please manually check that the file '{0}' will not be overwritten by this program.", report_file_name);
        press_any_key();
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    // Check if we are going to overwrite the previous report
    if config.generate_report && !config.force_overwrite {
        directory_check(&config.report_file_name);
    }

    let results = match parse_json(&config.scan_results_path) {
        Ok(raw_json) => process_json(&raw_json),
        Err(err) => {
            return Err(err);
        }
    };

    if config.generate_report {
        println!("✍️ Writing report...");
        if let Err(e) = save_processed_report(&results, &config.report_file_name) {
            println!("❌ Unable to write report!");
            println!("Error: {}", e.to_string());
        } else {
            println!("💾 Done!")
        }
    }

    if results.vulnerable_dependencies > 0 {
        println!("Results for {0}", results.project_name);
        println!("Found {0} vulnerable dependencies, with a total of {1} vulnerabilities", results.vulnerable_dependencies, results.found_vulnerabilities);
        if config.list_vulnerable_dependencies {
            println!("--- Vulnerable Dependencies ---");
            results.dependencies.iter().for_each(|dependency| println!("{0}", dependency))
        }
    } else {
        println!("🎉 All clear!")
    }

    Ok(())
}

fn process_json(json_to_process: &ReportJson) -> ProcessingResults {
    let mut total_vulnerabilities = 0;
    let mut vulnerable_dependencies = 0;
    let mut deps: Vec<String> = Vec::new();

    let dependencies = &json_to_process.dependencies;

    let longest_name = find_longest_name(&dependencies);

    for dependency in dependencies {
        for vulnerability in &dependency.vulnerabilities {
            total_vulnerabilities += vulnerability.len();
            vulnerable_dependencies += 1;
            if let Some(included_by) = &dependency.included_by {
                let spaces = produce_spacing(&longest_name, &dependency.file_name);
                deps.push(format!("{0}{1} from {2}", dependency.file_name, spaces, included_by[0].reference))
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

fn save_processed_report(results: &ProcessingResults, report_file_name: &str) -> Result<(), Box<dyn Error>> {
    let current_dir = env::current_dir()?;
    let file_path = current_dir.join(report_file_name);
    let mut file = File::create(file_path)?;
    let dependencies_str = results.dependencies.join("\n");
    let content = format!("{0} vulnerabilities\n{1} vulnerable dependencies\n\n--- List of vulnerable dependencies ---\n{2}", results.found_vulnerabilities, results.vulnerable_dependencies, dependencies_str);
    file.write_all(content.as_bytes())?;

    Ok(())
}

fn press_any_key() {
    println!("Press any key to continue...");
    io::stdin().read_exact(&mut [0]).unwrap();
}