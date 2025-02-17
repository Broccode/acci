#!/bin/bash
set -euo pipefail

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --metrics)
            METRICS_FILE="$2"
            shift 2
            ;;
        --endpoint)
            PUSHGATEWAY_ENDPOINT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "${METRICS_FILE:-}" ] || [ -z "${PUSHGATEWAY_ENDPOINT:-}" ]; then
    echo "Required parameters missing. Usage: $0 --metrics <file> --endpoint <url>"
    exit 1
fi

# Validate metrics file exists
if [ ! -f "$METRICS_FILE" ]; then
    echo "Metrics file not found: $METRICS_FILE"
    exit 1
fi

# Extract metrics from JSON
total_coverage=$(jq -r '.coverage.total' "$METRICS_FILE")
function_coverage=$(jq -r '.coverage.functions' "$METRICS_FILE")
branch_coverage=$(jq -r '.coverage.branches' "$METRICS_FILE")

# Extract component coverage
components=(auth core db api)
for component in "${components[@]}"; do
    component_coverage=$(jq -r ".coverage.components.${component}.coverage" "$METRICS_FILE")
    component_threshold=$(jq -r ".coverage.components.${component}.threshold" "$METRICS_FILE")
    declare "coverage_${component}=$component_coverage"
    declare "threshold_${component}=$component_threshold"
done

# Extract mutation metrics
mutation_score=$(jq -r '.mutation.score' "$METRICS_FILE")
killed_mutations=$(jq -r '.mutation.killed' "$METRICS_FILE")
total_mutations=$(jq -r '.mutation.total' "$METRICS_FILE")

# Extract performance metrics
mean_execution_time=$(jq -r '.performance.mean_execution_time' "$METRICS_FILE")
mean_throughput=$(jq -r '.performance.mean_throughput' "$METRICS_FILE")
p50_time=$(jq -r '.performance.percentiles.p50' "$METRICS_FILE")
p90_time=$(jq -r '.performance.percentiles.p90' "$METRICS_FILE")
p99_time=$(jq -r '.performance.percentiles.p99' "$METRICS_FILE")
memory_usage=$(jq -r '.performance.memory_usage' "$METRICS_FILE")

# Get Git information
GIT_COMMIT=$(git rev-parse HEAD)
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Create temporary file for metrics
TEMP_FILE=$(mktemp)
trap 'rm -f "$TEMP_FILE"' EXIT

# Write metrics in Prometheus format
cat > "$TEMP_FILE" << EOF
# HELP test_coverage_percentage Code coverage percentage by type
# TYPE test_coverage_percentage gauge
test_coverage_percentage{type="total"} $total_coverage
test_coverage_percentage{type="functions"} $function_coverage
test_coverage_percentage{type="branches"} $branch_coverage

# HELP test_component_coverage_percentage Code coverage percentage by component
# TYPE test_component_coverage_percentage gauge
EOF

# Add component coverage metrics
for component in "${components[@]}"; do
    coverage_var="coverage_${component}"
    threshold_var="threshold_${component}"
    echo "test_component_coverage_percentage{component=\"${component}\"} ${!coverage_var}" >> "$TEMP_FILE"
    echo "test_component_coverage_threshold{component=\"${component}\"} ${!threshold_var}" >> "$TEMP_FILE"
done

cat >> "$TEMP_FILE" << EOF

# HELP test_mutation_metrics Mutation testing metrics
# TYPE test_mutation_metrics gauge
test_mutation_score $mutation_score
test_mutations_killed $killed_mutations
test_mutations_total $total_mutations

# HELP test_execution_time Test execution time in seconds
# TYPE test_execution_time gauge
test_execution_time{type="mean"} $mean_execution_time
test_execution_time{type="p50"} $p50_time
test_execution_time{type="p90"} $p90_time
test_execution_time{type="p99"} $p99_time

# HELP test_throughput Test execution throughput
# TYPE test_throughput gauge
test_throughput{type="mean"} $mean_throughput

# HELP test_memory_usage Test memory usage in MB
# TYPE test_memory_usage gauge
test_memory_usage $memory_usage

# HELP test_git_info Git repository information
# TYPE test_git_info gauge
test_git_info{commit="$GIT_COMMIT",branch="$GIT_BRANCH"} 1

# HELP test_status Test execution status
# TYPE test_status gauge
test_status{type="coverage"} $(jq -r '.status.coverage_ok' "$METRICS_FILE")
test_status{type="mutation"} $(jq -r '.status.mutation_ok' "$METRICS_FILE")
test_status{type="performance"} $(jq -r '.status.performance_ok' "$METRICS_FILE")
EOF

# Push metrics to Pushgateway
if ! curl -s --data-binary "@$TEMP_FILE" "$PUSHGATEWAY_ENDPOINT/metrics/job/test_metrics/instance/$(hostname)"; then
    echo "Failed to push metrics to Pushgateway"
    exit 1
fi

echo "Successfully pushed metrics to Prometheus Pushgateway"
