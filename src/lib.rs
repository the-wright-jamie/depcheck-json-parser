use std::{error::Error, fs::File, io::Read};

use clap::Parser;
use colored::{ColoredString, Colorize};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Struct for the config
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Config {
    /// The path to the OWASP Dependency Checker JSON report
    scan_results_path: String,

    /// Display total severity ratings
    #[arg(short, long)]
    severity_ratings: bool,

    /// List the vulnerable dependencies from the report
    #[arg(short, long)]
    list_vulnerable_dependencies: bool,

    /// List details regarding CVEs on vulnerability
    #[arg(short, long)]
    details: bool,
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
    cvssv3: CVSSV3,
    cwes: Vec<Value>,
    description: String,
    notes: String,
    references: Vec<Value>,
    vulnerable_software: Vec<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
enum SeverityKind {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CVSSV3 {
    base_severity: SeverityKind,
}

fn parse_json(file_path: &str) -> Result<ReportJson, Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let json_value: Value = serde_json::from_str(&contents)?;
    let report_json: ReportJson = serde_json::from_value(json_value).expect("msg");

    return Ok(report_json);
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let parsed_json = match parse_json(&config.scan_results_path) {
        Ok(raw_json) => raw_json,
        Err(err) => {
            return Err(err);
        }
    };

    if count_vulnerable_dependencies(&parsed_json.dependencies) > 0 {
        print_summary(&parsed_json);
        if config.severity_ratings {
            print_severities(&parsed_json);
        }
        if config.list_vulnerable_dependencies {
            print_vulnerable_dependencies_list(&parsed_json.dependencies);
        }
        if config.details {
            print_cves(&parsed_json);
        }
    } else {
        println!("🎉 All clear!")
    }

    Ok(())
}

fn print_severities(json: &ReportJson) {
    println!("\n{}", "Severity Enumeration".bold().underline());
    let (mut critical_count, mut high_count, mut medium_count, mut low_count) = (0, 0, 0, 0);

    for dependency in &json.dependencies {
        for vulnerabilities in &dependency.vulnerabilities {
            vulnerabilities.iter().for_each(|vulnerability| {
                match vulnerability.cvssv3.base_severity {
                    SeverityKind::CRITICAL => critical_count += 1,
                    SeverityKind::HIGH => high_count += 1,
                    SeverityKind::MEDIUM => medium_count += 1,
                    SeverityKind::LOW => low_count += 1,
                }
            })
        }
    }

    println!(
        "{} {}",
        critical_count.to_string().bold(),
        coloured_severity(&SeverityKind::CRITICAL)
    );

    println!(
        "{} {}",
        high_count.to_string().bold(),
        coloured_severity(&SeverityKind::HIGH)
    );

    println!(
        "{} {}",
        medium_count.to_string().bold(),
        coloured_severity(&SeverityKind::MEDIUM)
    );
    println!(
        "{} {}",
        low_count.to_string().bold(),
        coloured_severity(&SeverityKind::LOW)
    );
}

fn print_summary(json: &ReportJson) {
    let vulnerable_dependencies: usize = count_vulnerable_dependencies(&json.dependencies);

    if json.project_info.name.is_empty() {
        println!(
            "{} {} found",
            vulnerable_dependencies.to_string().bold().red(),
            "vulnerable dependencies".bold()
        );
    } else {
        println!(
            "{} {} found in {}",
            vulnerable_dependencies.to_string().bold().red(),
            "vulnerable dependencies".bold(),
            json.project_info.name.red().bold(),
        );
    }
    let total_cves: usize = count_total_cves(&json.dependencies);
    println!(
        "{} {}",
        total_cves.to_string().bold().red(),
        "total CVEs".bold()
    );
}

fn count_vulnerable_dependencies(dependencies: &Vec<Dependency>) -> usize {
    let mut vulnerable_dependencies = 0;

    for dependency in dependencies {
        dependency
            .vulnerabilities
            .iter()
            .for_each(|_| vulnerable_dependencies += 1);
    }

    vulnerable_dependencies
}

fn count_total_cves(dependencies: &Vec<Dependency>) -> usize {
    let mut total_vulnerabilities = 0;

    for dependency in dependencies {
        for vulnerabilities in &dependency.vulnerabilities {
            total_vulnerabilities += vulnerabilities.len();
        }
    }

    total_vulnerabilities
}

fn print_vulnerable_dependencies_list(dependencies: &Vec<Dependency>) {
    println!("\n{}", "Vulnerable Dependencies List".bold().underline());

    let longest_name_size = find_longest_name(dependencies);

    for dependency in dependencies {
        dependency.vulnerabilities.iter().for_each(|_| {
            print_single_vulnerable_dependency(&longest_name_size, &dependency);
        })
    }
}

fn print_single_vulnerable_dependency(longest_name_size: &usize, dependency: &Dependency) {
    if let Some(included_by) = &dependency.included_by {
        let spaces = " ".repeat(how_many_spaces(&longest_name_size, &dependency.file_name));
        println!(
            "{0}{1} from {2}",
            dependency.file_name.yellow(),
            spaces,
            included_by[0].reference.bold()
        );
    } else {
        println!("{}", dependency.file_name.yellow());
    }
}

fn print_cves(json_to_process: &ReportJson) {
    println!("\n{}", "Vulnerability Details".bold().underline());

    let dependencies = &json_to_process.dependencies;
    let longest_name_size = find_longest_name(dependencies);

    for dependency in dependencies {
        for vulnerabilities in &dependency.vulnerabilities {
            print_single_vulnerable_dependency(&longest_name_size, &dependency);
            for vulnerability in vulnerabilities {
                println!(
                    "{1} ({0})\n{2}\n",
                    coloured_severity(&vulnerability.cvssv3.base_severity),
                    vulnerability.name.red().bold(),
                    vulnerability.description
                );
            }
        }
    }
}

fn coloured_severity(severity: &SeverityKind) -> ColoredString {
    match severity {
        SeverityKind::CRITICAL => "CRITICAL".red().bold(),
        SeverityKind::HIGH => "HIGH".truecolor(255, 165, 0),
        SeverityKind::MEDIUM => "MEDIUM".yellow(),
        SeverityKind::LOW => "LOW".blue(),
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

fn how_many_spaces(longest_name: &usize, current_name: &str) -> usize {
    longest_name - current_name.len()
}
