//! Test reporting module for collecting and analyzing test results.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path, time::Duration};

/// Represents a comprehensive test report including coverage and execution metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct TestReport {
    /// Total number of tests executed
    pub total_tests: usize,
    /// Number of successful tests
    pub passed_tests: usize,
    /// Number of failed tests
    pub failed_tests: usize,
    /// Test coverage percentage
    pub coverage: f64,
    /// Total test execution duration
    pub duration: Duration,
    /// Coverage by component
    pub component_coverage: ComponentCoverage,
    /// Test execution metrics
    pub execution_metrics: ExecutionMetrics,
}

/// Coverage metrics for different components
#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentCoverage {
    /// Authentication module coverage
    pub auth_coverage: f64,
    /// Core module coverage
    pub core_coverage: f64,
    /// Database module coverage
    pub db_coverage: f64,
    /// API module coverage
    pub api_coverage: f64,
    /// Frontend module coverage
    pub frontend_coverage: f64,
}

/// Metrics related to test execution
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionMetrics {
    /// Average test duration
    pub avg_duration: Duration,
    /// Maximum test duration
    pub max_duration: Duration,
    /// Number of flaky tests
    pub flaky_tests: usize,
    /// Number of slow tests
    pub slow_tests: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoverageReport {
    timestamp: String,
    thresholds: Thresholds,
    coverage: Coverage,
    status: String,
    error_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct Thresholds {
    critical: f64,
    core: f64,
    general: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Coverage {
    #[serde(rename = "acci-auth")]
    auth: Option<f64>,
    #[serde(rename = "acci-core")]
    core: Option<f64>,
    #[serde(rename = "acci-db")]
    db: Option<f64>,
    #[serde(rename = "acci-api")]
    api: Option<f64>,
    #[serde(rename = "acci-frontend")]
    frontend: Option<f64>,
}

impl TestReport {
    /// Generate a new test report by collecting metrics from test execution
    pub fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        // Read coverage report
        let coverage_report: CoverageReport =
            serde_json::from_str(&fs::read_to_string("coverage-report.json")?)?;

        // Parse test output to collect execution metrics
        let test_output = fs::read_to_string("target/test-output.log")?;
        let (total, passed, failed, duration, test_durations) = parse_test_output(&test_output)?;

        // Calculate execution metrics
        let avg_duration = calculate_average_duration(&test_durations);
        let max_duration = *test_durations
            .values()
            .max()
            .unwrap_or(&Duration::default());
        let slow_tests = count_slow_tests(&test_durations, Duration::from_secs(5));
        let flaky_tests = count_flaky_tests(&test_output);

        Ok(Self {
            total_tests: total,
            passed_tests: passed,
            failed_tests: failed,
            coverage: calculate_overall_coverage(&coverage_report.coverage),
            duration,
            component_coverage: ComponentCoverage {
                auth_coverage: coverage_report.coverage.auth.unwrap_or(0.0),
                core_coverage: coverage_report.coverage.core.unwrap_or(0.0),
                db_coverage: coverage_report.coverage.db.unwrap_or(0.0),
                api_coverage: coverage_report.coverage.api.unwrap_or(0.0),
                frontend_coverage: coverage_report.coverage.frontend.unwrap_or(0.0),
            },
            execution_metrics: ExecutionMetrics {
                avg_duration,
                max_duration,
                flaky_tests,
                slow_tests,
            },
        })
    }

    /// Export the report as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Check if the report meets quality thresholds
    pub fn meets_thresholds(&self) -> bool {
        self.component_coverage.auth_coverage >= 95.0
            && self.component_coverage.core_coverage >= 90.0
            && self.component_coverage.db_coverage >= 90.0
            && self.component_coverage.api_coverage >= 80.0
            && self.component_coverage.frontend_coverage >= 80.0
            && self.passed_tests as f64 / self.total_tests as f64 >= 0.95
    }

    /// Generate a summary of the test results
    pub fn generate_summary(&self) -> String {
        format!(
            "Test Report Summary:
            Total Tests: {}
            Passed: {} ({:.1}%)
            Failed: {} ({:.1}%)
            Overall Coverage: {:.1}%
            Duration: {:?}

            Component Coverage:
            - Auth: {:.1}%
            - Core: {:.1}%
            - DB: {:.1}%
            - API: {:.1}%
            - Frontend: {:.1}%

            Execution Metrics:
            - Average Duration: {:?}
            - Max Duration: {:?}
            - Flaky Tests: {}
            - Slow Tests: {}",
            self.total_tests,
            self.passed_tests,
            self.passed_tests as f64 / self.total_tests as f64 * 100.0,
            self.failed_tests,
            self.failed_tests as f64 / self.total_tests as f64 * 100.0,
            self.coverage,
            self.duration,
            self.component_coverage.auth_coverage,
            self.component_coverage.core_coverage,
            self.component_coverage.db_coverage,
            self.component_coverage.api_coverage,
            self.component_coverage.frontend_coverage,
            self.execution_metrics.avg_duration,
            self.execution_metrics.max_duration,
            self.execution_metrics.flaky_tests,
            self.execution_metrics.slow_tests
        )
    }

    /// Save the report to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.to_json()?;
        fs::write(path, json)?;
        Ok(())
    }
}

// Helper functions for parsing test output and calculating metrics

fn parse_test_output(
    output: &str,
) -> Result<(usize, usize, usize, Duration, HashMap<String, Duration>), Box<dyn std::error::Error>>
{
    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut total_duration = Duration::default();
    let mut test_durations = HashMap::new();

    for line in output.lines() {
        if line.contains("test result:") {
            // Parse test summary line
            let parts: Vec<&str> = line.split(',').collect();
            for part in parts {
                if part.contains("passed") {
                    passed = part
                        .trim()
                        .split_whitespace()
                        .next()
                        .unwrap_or("0")
                        .parse()?;
                    total += passed;
                } else if part.contains("failed") {
                    failed = part
                        .trim()
                        .split_whitespace()
                        .next()
                        .unwrap_or("0")
                        .parse()?;
                    total += failed;
                }
            }
        } else if line.contains("test") && line.contains("...") {
            // Parse individual test duration
            if let Some((test_name, duration)) = parse_test_line(line) {
                test_durations.insert(test_name.to_string(), duration);
                total_duration += duration;
            }
        }
    }

    Ok((total, passed, failed, total_duration, test_durations))
}

fn parse_test_line(line: &str) -> Option<(&str, Duration)> {
    let parts: Vec<&str> = line.split("...").collect();
    if parts.len() != 2 {
        return None;
    }

    let test_name = parts[0].trim();
    let duration_str = parts[1].trim();

    if duration_str.contains("ok") {
        if let Some(duration_ms) = duration_str
            .split_whitespace()
            .find(|s| s.ends_with("ms"))
            .and_then(|s| s.trim_end_matches("ms").parse::<u64>().ok())
        {
            return Some((test_name, Duration::from_millis(duration_ms)));
        }
    }

    None
}

fn calculate_average_duration(durations: &HashMap<String, Duration>) -> Duration {
    if durations.is_empty() {
        return Duration::default();
    }

    let total: Duration = durations.values().sum();
    Duration::from_nanos((total.as_nanos() / durations.len() as u128) as u64)
}

fn count_slow_tests(durations: &HashMap<String, Duration>, threshold: Duration) -> usize {
    durations.values().filter(|&&d| d > threshold).count()
}

fn count_flaky_tests(output: &str) -> usize {
    output
        .lines()
        .filter(|line| {
            line.contains("test") && line.contains("failed") && line.contains("retrying")
        })
        .count()
}

fn calculate_overall_coverage(coverage: &Coverage) -> f64 {
    let mut total = 0.0;
    let mut count = 0;

    if let Some(auth) = coverage.auth {
        total += auth;
        count += 1;
    }
    if let Some(core) = coverage.core {
        total += core;
        count += 1;
    }
    if let Some(db) = coverage.db {
        total += db;
        count += 1;
    }
    if let Some(api) = coverage.api {
        total += api;
        count += 1;
    }
    if let Some(frontend) = coverage.frontend {
        total += frontend;
        count += 1;
    }

    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}
