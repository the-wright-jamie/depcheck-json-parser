use std::{error::Error, fs::File, io::Read};

use serde::{Deserialize, Serialize};
use clap::Parser;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Config {
    /// The path to the OWASP Dependency Checker JSON report
    scan_results_path: String,

    /// Generates and a saves a machine readable report for later processing.
    /// If not present, will just print results to terminal.
    #[arg(short, long)]
    generate_report: bool,

    /// Count the total found vulnerabilities 
    #[arg(short, long)]
    count_vulnerabilities: bool,

    /// List the vulnerable packages as part of the report
    #[arg(short, long)]
    list_packages: bool,
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
    md5: String,
    sha1: String,
    sha256: String,
    project_references: Vec<Value>,
    included_by: Option<Vec<Value>>,
    evidence_collected: EvidenceCollected,
    packages: Option<Vec<Value>>,
    vulnerability_ids: Option<Vec<VulnerabilityId>>,
    vulnerabilities: Option<Vec<Vulnerability>>,
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

fn parse_json(file_path: &str) -> Result<ReportJson, Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let json_value: Value = serde_json::from_str(&contents)?;
    let report_json: ReportJson = serde_json::from_value(json_value).expect("msg");

    return Ok(report_json)
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let json_result = parse_json(&config.scan_results_path);
    let json;

    match json_result {
        Ok(raw_json) => {
            json = raw_json;
        }
        Err(raw_json) => {
            println!("{raw_json}");
            return Err(raw_json);
        }
    }
    
    let vulns = count_vulnerable_deps(&json);
    let cve_list = list_vulnerable_deps(&json);

    println!("Found {vulns} vulnerable dependencies");
    println!("Vulnerable Dependencies List: ");
    for cve in cve_list {
        println!("{cve}");
    }

    Ok(())
}

fn count_vulnerable_deps(json_to_process: &ReportJson) -> usize {
    let mut vulns = 0;
    let dependencies = &json_to_process.dependencies;

    for dependency in dependencies {
        for _vulnerabilities in &dependency.vulnerabilities {
            vulns += 1;
        }
    }

    vulns
}

fn list_vulnerable_deps(json_to_process: &ReportJson) -> Vec<&str> {
    let mut deps: Vec<&str> = Vec::new();
    let dependencies = &json_to_process.dependencies;

    for dependency in dependencies {
        for _vulnerabilities in &dependency.vulnerabilities {
            deps.push(&dependency.file_name)
        }
    }

    deps
}

// TODO: TESTS
/*#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expect_no_vulns() {
        let expected_result = 0;
        let json_result = parse_json("test-data/dependency-check-report-1.json");
        let json;

        match json_result {
            Ok(raw_json) => {
                json = raw_json;
            }
            Err(raw_json) => {
                assert_eq!(true, false);
                return;
            }
        }

        assert_eq!(expected_result, count_vulnerable_deps(&json));
    }

    #[test]
    fn expect_two_vulns() {
        let expected_result = 2;
        let json_result = parse_json("test-data/dependency-check-report-2.json");
        let json;

        match json_result {
            Ok(raw_json) => {
                json = raw_json;
            }
            Err(raw_json) => {
                assert_eq!(true, false);
                return;
            }
        }
        assert_eq!(expected_result, count_vulnerable_deps(&json));
    }

    #[test]
    fn expect_ten_vulns() {
        let expected_result = 10;
        let json_result = parse_json("test-data/dependency-check-report-3.json");
        let json;

        match json_result {
            Ok(raw_json) => {
                json = raw_json;
            }
            Err(raw_json) => {
                assert_eq!(true, false);
                return;
            }
        }
        assert_eq!(expected_result, count_vulnerable_deps(&json));
    }

    #[test]
    fn expect_three_deps() {
        let expected_result = 3;
        let json_result = parse_json("test-data/dependency-check-report-1.json");
        let json;

        match json_result {
            Ok(raw_json) => {
                json = raw_json;
            }
            Err(raw_json) => {
                assert_eq!(true, false);
                return;
            }
        }

        assert_eq!(expected_result, count_dependencies(&json));
    }
}*/