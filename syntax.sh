#!/usr/bin/env bash
set -euo pipefail

# Default values
light_theme=""
dark_theme=""
destination_path="assets/css/extended/syntax.css"

# Help message
usage() {
  cat <<EOF
Usage: $0 [options] [--] [light-theme] [dark-theme]

Options:
  -h, --help                Show this help message and exit
  --light-theme=LIGHT_THEME Set the light theme
  --dark-theme=DARK_THEME   Set the dark theme
  --destination-path=PATH   Set the destination path for the output file

Positional arguments:
  light-theme              Light theme (alternative to --light-theme)
  dark-theme               Dark theme (alternative to --dark-theme)
EOF
}

positional_arg_counter=0

# Parse options and arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      usage
      exit 0
      ;;
    --light-theme=*)
      light_theme="${1#*=}"
      positional_arg_counter=$((positional_arg_counter + 1))
      shift
      ;;
    --dark-theme=*)
      dark_theme="${1#*=}"
      positional_arg_counter=$((positional_arg_counter + 1))
      shift
      ;;
    --destination-path=*)
      destination_path="${1#*=}"
      shift
      ;;
    *)
      if [[ $positional_arg_counter -eq 0 ]]; then
        light_theme="$1"
      elif [[ $positional_arg_counter -eq 1 ]]; then
        dark_theme="$1"
      else
        echo "Error: Too many arguments" >&2
        usage
        exit 1
      fi
      positional_arg_counter=$((positional_arg_counter + 1))
      shift
      ;;
  esac
done

if [[ -z "$light_theme" ]] || [[ -z "$dark_theme" ]]; then
  echo "Error: Missing arguments" >&2
  usage
  exit 1
fi

# Create directory structure if needed
mkdir -p "$(dirname "$destination_path")"

# Debug output
echo "Generating light theme: $light_theme"
echo "Output file: $destination_path"

# Generate light theme
hugo gen chromastyles --style="$light_theme" > "$destination_path"

# Verify light theme generation
if [ ! -f "$destination_path" ]; then
  echo "Error: Failed to create light theme file!"
  exit 1
fi

# Generate dark theme
echo "Appending dark theme: $dark_theme"
{
    echo "@media (prefers-color-scheme: dark) {"
    hugo gen chromastyles --style="$dark_theme" | sed -r 's/(^\/\*[^*]*\*\/)?(.+)/\1 .dark\2/'
    echo "}"
} >> "$destination_path"

# Final verification
if [ $? -eq 0 ]; then
  echo "Successfully generated syntax.css with both themes!"
else
  echo "Error: Failed to append dark theme!"
  exit 1
fi