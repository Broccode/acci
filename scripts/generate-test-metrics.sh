#!/bin/bash
set -euo pipefail

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage)
            COVERAGE_FILE="$2"
            shift 2
            ;;
        --mutation)
            MUTATION_FILE="$2"
            shift 2
            ;;
        --benchmarks)
            BENCHMARK_FILE="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Set default config file location
CONFIG_FILE=${CONFIG_FILE:-"config/test-metrics.json"}

# Validate required files
for file in "$COVERAGE_FILE" "$MUTATION_FILE" "$BENCHMARK_FILE" "$CONFIG_FILE"; do
    if [ ! -f "$file" ]; then
        echo "Required file not found: $file"
        exit 1
    fi
done

# Load thresholds from config
total_coverage_threshold=$(jq -r '.coverage.total.threshold' "$CONFIG_FILE")
critical_coverage_threshold=$(jq -r '.coverage.critical.threshold' "$CONFIG_FILE")
function_coverage_threshold=$(jq -r '.coverage.functions.threshold' "$CONFIG_FILE")
branch_coverage_threshold=$(jq -r '.coverage.branches.threshold' "$CONFIG_FILE")
mutation_score_threshold=$(jq -r '.mutation.score.threshold' "$CONFIG_FILE")
performance_regression_threshold=$(jq -r '.performance.regression.threshold' "$CONFIG_FILE")
max_execution_time=$(jq -r '.performance.execution_time.threshold' "$CONFIG_FILE")
max_memory_usage=$(jq -r '.performance.memory_usage.threshold' "$CONFIG_FILE")

# Extract coverage metrics
total_coverage=$(jq -r '.data[0].totals.lines.percent' "$COVERAGE_FILE")
function_coverage=$(jq -r '.data[0].totals.functions.percent' "$COVERAGE_FILE")
branch_coverage=$(jq -r '.data[0].totals.branches.percent' "$COVERAGE_FILE")

# Extract component coverage
components=("auth" "core" "db" "api")
declare -A component_coverage
for component in "${components[@]}"; do
    threshold=$(jq -r ".components.${component}.coverage.threshold" "$CONFIG_FILE")
    coverage=$(jq -r ".data[0].files[] | select(.file | startswith(\"src/${component}/\")) | .lines.percent" "$COVERAGE_FILE" | awk '{ sum += $1; n++ } END { print sum/n }')
    component_coverage[$component]=$coverage
    component_thresholds[$component]=$threshold
done

# Extract mutation score
mutation_score=$(jq -r '.score' "$MUTATION_FILE")
killed_mutations=$(jq -r '.killed' "$MUTATION_FILE")
total_mutations=$(jq -r '.total' "$MUTATION_FILE")

# Extract benchmark metrics
benchmark_mean=$(jq -r '.benchmarks | map(.mean) | add / length' "$BENCHMARK_FILE")
benchmark_throughput=$(jq -r '.benchmarks | map(.throughput) | add / length' "$BENCHMARK_FILE")
benchmark_p50=$(jq -r '.benchmarks | map(.percentiles."0.5") | add / length' "$BENCHMARK_FILE")
benchmark_p90=$(jq -r '.benchmarks | map(.percentiles."0.9") | add / length' "$BENCHMARK_FILE")
benchmark_p99=$(jq -r '.benchmarks | map(.percentiles."0.99") | add / length' "$BENCHMARK_FILE")
memory_usage=$(jq -r '.benchmarks | map(.memory_usage) | add / length' "$BENCHMARK_FILE")

# Generate timestamp
timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Create metrics report
cat > "$OUTPUT_FILE" << EOF
{
    "timestamp": "$timestamp",
    "coverage": {
        "total": $total_coverage,
        "functions": $function_coverage,
        "branches": $branch_coverage,
        "components": {
EOF

# Add component coverage
for component in "${components[@]}"; do
    cat >> "$OUTPUT_FILE" << EOF
            "${component}": {
                "coverage": ${component_coverage[$component]},
                "threshold": ${component_thresholds[$component]}
            }$([ "$component" != "${components[-1]}" ] && echo ",")
EOF
done

cat >> "$OUTPUT_FILE" << EOF
        }
    },
    "mutation": {
        "score": $mutation_score,
        "killed": $killed_mutations,
        "total": $total_mutations
    },
    "performance": {
        "mean_execution_time": $benchmark_mean,
        "mean_throughput": $benchmark_throughput,
        "percentiles": {
            "p50": $benchmark_p50,
            "p90": $benchmark_p90,
            "p99": $benchmark_p99
        },
        "memory_usage": $memory_usage
    },
    "thresholds": {
        "coverage": {
            "total": $total_coverage_threshold,
            "critical": $critical_coverage_threshold,
            "functions": $function_coverage_threshold,
            "branches": $branch_coverage_threshold
        },
        "mutation": {
            "score": $mutation_score_threshold
        },
        "performance": {
            "regression": $performance_regression_threshold,
            "execution_time": $max_execution_time,
            "memory_usage": $max_memory_usage
        }
    },
    "status": {
        "coverage_ok": $(( $(echo "$total_coverage >= $total_coverage_threshold" | bc -l) )),
        "mutation_ok": $(( $(echo "$mutation_score >= $mutation_score_threshold" | bc -l) )),
        "performance_ok": $(( $(echo "$benchmark_mean <= $max_execution_time" | bc -l) && $(echo "$memory_usage <= $max_memory_usage" | bc -l) ))
    }
}
EOF

# Validate metrics against thresholds
echo "Validating metrics against thresholds..."

# Check total coverage
if (( $(echo "$total_coverage < $total_coverage_threshold" | bc -l) )); then
    echo "Total coverage below threshold: ${total_coverage}% < ${total_coverage_threshold}%"
    exit 1
fi

# Check component coverage
for component in "${components[@]}"; do
    if (( $(echo "${component_coverage[$component]} < ${component_thresholds[$component]}" | bc -l) )); then
        echo "Component coverage below threshold for ${component}: ${component_coverage[$component]}% < ${component_thresholds[$component]}%"
        exit 1
    fi
done

# Check mutation score
if (( $(echo "$mutation_score < $mutation_score_threshold" | bc -l) )); then
    echo "Mutation score below threshold: ${mutation_score}% < ${mutation_score_threshold}%"
    exit 1
fi

# Check performance metrics
if (( $(echo "$benchmark_mean > $max_execution_time" | bc -l) )); then
    echo "Execution time above threshold: ${benchmark_mean}s > ${max_execution_time}s"
    exit 1
fi

if (( $(echo "$memory_usage > $max_memory_usage" | bc -l) )); then
    echo "Memory usage above threshold: ${memory_usage}MB > ${max_memory_usage}MB"
    exit 1
fi

echo "All metrics within acceptable thresholds"
