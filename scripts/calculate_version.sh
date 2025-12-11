#!/usr/bin/env bash
set -euo pipefail

# calculate_version.sh - Version calculation for GitHub Actions workflows
# Usage: calculate_version.sh --type <release|rc> --bump <major|minor|patch> [--pr-number NUM] [--run-number NUM]

# Default values
VERSION_TYPE=""
BUMP_TYPE=""
PR_NUMBER=""
RUN_NUMBER=""
OUTPUT_FILE="${GITHUB_OUTPUT:-/dev/stdout}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --type)
      VERSION_TYPE="$2"
      shift 2
      ;;
    --bump)
      BUMP_TYPE="$2"
      shift 2
      ;;
    --pr-number)
      PR_NUMBER="$2"
      shift 2
      ;;
    --run-number)
      RUN_NUMBER="$2"
      shift 2
      ;;
    --help)
      cat << EOF
Usage: calculate_version.sh [OPTIONS]

Calculate semantic version based on latest git tag.

OPTIONS:
  --type TYPE          Version type: 'release' or 'rc' (required)
  --bump BUMP          Bump type: 'major', 'minor', or 'patch' (required)
  --pr-number NUM      PR number for RC versions (required if --type rc)
  --run-number NUM     Run number for RC versions (required if --type rc)
  --help               Show this help message

OUTPUTS (to \$GITHUB_OUTPUT):
  new_version          The calculated version string
  latest_tag           The latest tag found

EXAMPLES:
  # Release version (patch bump)
  calculate_version.sh --type release --bump patch
  # Output: new_version=v1.2.4

  # Development version for PR #123, run #45
  calculate_version.sh --type rc --bump patch --pr-number 123 --run-number 45
  # Output: new_version=1.2.4.dev123045

EXIT CODES:
  0  Success
  1  Invalid arguments or git error
EOF
      exit 0
      ;;
    *)
      echo -e "${RED}Error: Unknown argument '$1'${NC}" >&2
      echo "Use --help for usage information" >&2
      exit 1
      ;;
  esac
done

# Validate required arguments
if [[ -z "$VERSION_TYPE" ]]; then
  echo -e "${RED}Error: --type is required${NC}" >&2
  exit 1
fi

if [[ "$VERSION_TYPE" != "release" && "$VERSION_TYPE" != "rc" ]]; then
  echo -e "${RED}Error: --type must be 'release' or 'rc'${NC}" >&2
  exit 1
fi

if [[ -z "$BUMP_TYPE" ]]; then
  echo -e "${RED}Error: --bump is required${NC}" >&2
  exit 1
fi

if [[ "$BUMP_TYPE" != "major" && "$BUMP_TYPE" != "minor" && "$BUMP_TYPE" != "patch" ]]; then
  echo -e "${RED}Error: --bump must be 'major', 'minor', or 'patch'${NC}" >&2
  exit 1
fi

if [[ "$VERSION_TYPE" == "rc" ]]; then
  if [[ -z "$PR_NUMBER" ]]; then
    echo -e "${RED}Error: --pr-number is required for RC versions${NC}" >&2
    exit 1
  fi
  if [[ -z "$RUN_NUMBER" ]]; then
    echo -e "${RED}Error: --run-number is required for RC versions${NC}" >&2
    exit 1
  fi
fi

# Get latest tag
echo "=== Getting Latest Tag ===" >&2
latest_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
echo -e "${GREEN}Latest tag: $latest_tag${NC}" >&2

# Strip 'v' prefix for version calculation
version=${latest_tag#v}

# Parse version components
IFS='.' read -r major minor patch <<< "$version"

# Validate parsed components
if ! [[ "$major" =~ ^[0-9]+$ ]] || ! [[ "$minor" =~ ^[0-9]+$ ]] || ! [[ "$patch" =~ ^[0-9]+$ ]]; then
  echo -e "${RED}Error: Could not parse version from tag '$latest_tag'${NC}" >&2
  echo "Expected format: v1.2.3" >&2
  exit 1
fi

echo "Parsed version: $major.$minor.$patch" >&2

# Apply version bump
case $BUMP_TYPE in
  major)
    major=$((major + 1))
    minor=0
    patch=0
    echo -e "${YELLOW}Bumping MAJOR version${NC}" >&2
    ;;
  minor)
    minor=$((minor + 1))
    patch=0
    echo -e "${YELLOW}Bumping MINOR version${NC}" >&2
    ;;
  patch)
    patch=$((patch + 1))
    echo -e "${YELLOW}Bumping PATCH version${NC}" >&2
    ;;
esac

# Generate version based on type
if [[ "$VERSION_TYPE" == "release" ]]; then
  new_version="v${major}.${minor}.${patch}"
  echo -e "${GREEN}Generated release version: $new_version${NC}" >&2
elif [[ "$VERSION_TYPE" == "rc" ]]; then
  # Development version format: major.minor.patch.dev + PR# + padded RUN#
  # Pad run number to 3 digits to prevent ambiguity
  # Example: 1.2.3.dev123045 (PR 123, run 45)
  printf -v padded_run "%03d" "$RUN_NUMBER"
  new_version="${major}.${minor}.${patch}.dev${PR_NUMBER}${padded_run}"
  echo -e "${GREEN}Generated dev version: $new_version${NC}" >&2
fi

# Output for GitHub Actions
echo "latest_tag=$latest_tag" >> "$OUTPUT_FILE"
echo "new_version=$new_version" >> "$OUTPUT_FILE"

echo "" >&2
echo "=== Summary ===" >&2
echo "Latest tag:  $latest_tag" >&2
echo "Bump type:   $BUMP_TYPE" >&2
echo "New version: $new_version" >&2