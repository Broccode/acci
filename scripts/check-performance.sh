#!/bin/bash
set -euo pipefail

BENCHMARK_FILE=$1
REGRESSION_THRESHOLD=5 # 5% regression threshold

# Function to calculate percentage difference
calc_percentage_diff() {
    local current=$1
    local baseline=$2
    echo "scale=2; (($current - $baseline) / $baseline) * 100" | bc
}

# Load baseline benchmarks if they exist
if [ -f "benchmark-baseline.json" ]; then
    echo "Comparing against baseline benchmarks..."

    # Extract benchmark metrics
    current_metrics=$(jq -r '.benchmarks[] | "\(.name) \(.mean)"' "$BENCHMARK_FILE")
    baseline_metrics=$(jq -r '.benchmarks[] | "\(.name) \(.mean)"' benchmark-baseline.json)

    # Compare each benchmark
    while IFS=' ' read -r name current_mean; do
        baseline_mean=$(echo "$baseline_metrics" | grep "^$name " | cut -d' ' -f2)
        if [ -n "$baseline_mean" ]; then
            diff=$(calc_percentage_diff "$current_mean" "$baseline_mean")
            if (( $(echo "$diff > $REGRESSION_THRESHOLD" | bc -l) )); then
                echo "Performance regression detected in $name: ${diff}% slower"
                exit 1
            fi
        fi
    done <<< "$current_metrics"

    echo "No significant performance regressions detected"
else
    echo "No baseline benchmarks found, creating new baseline..."
    cp "$BENCHMARK_FILE" benchmark-baseline.json
fi

# Update baseline if on main branch
if [ "${GITHUB_REF:-}" = "refs/heads/main" ] || [ "${GITHUB_REF:-}" = "refs/heads/master" ]; then
    cp "$BENCHMARK_FILE" benchmark-baseline.json
fi
