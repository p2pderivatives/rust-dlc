#!/bin/bash

set -e

# Function to get features from a Cargo.toml file
get_features() {
    local cargo_toml="$1"
    yq e '.features | keys | .[]' "$cargo_toml" 2>/dev/null || true
}

# Function to recursively find all Cargo.toml files
find_cargo_tomls() {
    find . -name Cargo.toml | grep -v '/target/'
}

# Collect all unique features
collect_features() {
    local all_features=()
    while IFS= read -r toml; do
        while IFS= read -r feature; do
            all_features+=("$feature")
        done < <(get_features "$toml")
    done < <(find_cargo_tomls)
    printf '%s\n' "${all_features[@]}" | sort -u
}

# Main script
EXCLUDE_FEATURE="${1:-}"
if [ -z "$EXCLUDE_FEATURE" ]; then
    echo "Usage: $0 <feature_to_exclude>"
    exit 1
fi

# Collect all unique features except the excluded one
FEATURES=$(collect_features | grep -v "^$EXCLUDE_FEATURE$" | tr '\n' ',' | sed 's/,$//')

# Run cargo test with all features except the excluded one
echo "Running tests with all features except '$EXCLUDE_FEATURE'"
cargo test --all --features "$FEATURES"
