use std::{error::Error};

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
}

#[derive(Debug, Deserialize, Serialize)]
struct VulnerabilityId {
    id: String,
    confidence: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceCollected {
    vendor_evidence: Vec<Value>,
    product_evidence: Vec<Value>,
    version_evidence: Vec<Value>,
}

fn parse_json(file_path: &str) -> ReportJson {
    let text = std::fs::read_to_string(file_path).unwrap();

    let value: Value = serde_json::from_str(&text).expect("Failed to parse JSON");

    serde_json::from_value::<ReportJson>(value).expect("Failed to parse")
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let json = parse_json(&config.scan_results_path);

    let dependencies = count_dependencies(&json);
    let vulns = count_vulnerabilities(&json);
    let discrete_vulns = count_discrete_vulnerabilities(&json);
    let cve_list = list_cves(&json);

    println!("Found {vulns} vulns across {dependencies} ({discrete_vulns} discrete vulns)");
    println!("CVE List: ");
    for cve in cve_list {
        println!("{cve}");
    }

    Ok(())
}

fn count_dependencies(json_to_process: &ReportJson) -> usize {
    json_to_process.dependencies.len()
}

fn count_vulnerabilities(json_to_process: &ReportJson) -> usize {
    let mut vulns = 0;
    let dependencies = &json_to_process.dependencies;

    for dependency in dependencies {
        for _vulnerabilities in &dependency.vulnerability_ids {
            vulns += 1;
        }
    }

    vulns
}

fn count_discrete_vulnerabilities(json_to_process: &ReportJson) -> usize {
    let mut vulns = 0;
    let dependencies = &json_to_process.dependencies;
    let mut cves: Vec<&str> = Vec::new();

    for dependency in dependencies {
        for vulnerabilities in &dependency.vulnerability_ids {
            for vulnerability in vulnerabilities {
                let mut discrete = true;

                for cve in &cves {
                    if cve.eq(&vulnerability.id) {
                        discrete = false;
                        break;
                    }
                }

                if discrete {
                    vulns += 1;
                    cves.push(&vulnerability.id);
                }
            }
        }
    }

    vulns
}

fn list_cves(json_to_process: &ReportJson) -> Vec<&str> {
    let dependencies = &json_to_process.dependencies;
    let mut cves: Vec<&str> = Vec::new();

    for dependency in dependencies {
        for vulnerabilities in &dependency.vulnerability_ids {
            for vulnerability in vulnerabilities {
                let mut discrete = true;

                for cve in &cves {
                    if cve.eq(&vulnerability.id) {
                        discrete = false;
                        break;
                    }
                }

                if discrete {
                    cves.push(&vulnerability.id);
                }
            }
        }
    }

    cves
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expect_no_vulns() {
        let expected_result = 0;
        let json = parse_json("test-data/dependency-check-report-1.json");
        assert_eq!(expected_result, count_vulnerabilities(json));
    }

    #[test]
    fn expect_two_vulns() {
        let expected_result = 2;
        let json = parse_json("test-data/dependency-check-report-2.json");
        assert_eq!(expected_result, count_vulnerabilities(json));
    }

    #[test]
    fn expect_ten_vulns() {
        let expected_result = 10;
        let json = parse_json("test-data/dependency-check-report-3.json");
        assert_eq!(expected_result, count_vulnerabilities(json));
    }

    #[test]
    fn expect_three_deps() {
        let expected_result = 3;
        let json = parse_json("test-data/dependency-check-report-1.json");
        assert_eq!(expected_result, count_dependencies(json));
    }
}