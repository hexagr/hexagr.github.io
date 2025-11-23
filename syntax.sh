#!/usr/bin/env bash
set -euo pipefail

# Defaults
light_theme=""
dark_theme=""
destination_path="assets/css/extended/syntax.css"

# Usage help
usage() {
  cat <<EOF
Usage: $0 [options] [--] [light-theme] [dark-theme]

Options:
  -h, --help                  Show this help message and exit
  --light-theme=THEME        Set the light theme (e.g. abap)
  --dark-theme=THEME         Set the dark theme (e.g. monokai)
  --destination-path=PATH    Set output file path (default: assets/css/extended/syntax.css)

Positional arguments:
  light-theme                Light theme name (if not using --light-theme)
  dark-theme                 Dark theme name (if not using --dark-theme)

Examples:
  $0 abap monokai
  $0 --light-theme=github --dark-theme=dracula
EOF
}

# Parse options
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage; exit 0 ;;
    --light-theme=*)
      light_theme="${1#*=}"; shift ;;
    --dark-theme=*)
      dark_theme="${1#*=}"; shift ;;
    --destination-path=*)
      destination_path="${1#*=}"; shift ;;
    *)
      if [[ -z "$light_theme" ]]; then
        light_theme="$1"
      elif [[ -z "$dark_theme" ]]; then
        dark_theme="$1"
      else
        echo "Error: Too many positional arguments"; usage; exit 1
      fi
      shift ;;
  esac
done

# Validation
if [[ -z "$light_theme" || -z "$dark_theme" ]]; then
  echo "Error: Light and dark themes are required."
  usage
  exit 1
fi

# Create target directory if needed
mkdir -p "$(dirname "$destination_path")"

# Generate syntax styles
{
  echo "/* Light theme: $light_theme */"
  hugo gen chromastyles --style="$light_theme" | sed 's/^/body:not(.dark) /'

  echo ""
  echo "/* Dark theme: $dark_theme */"
  hugo gen chromastyles --style="$dark_theme" | sed 's/^/body.dark /'
} > "$destination_path"

echo "✅ Syntax highlighting CSS written to: $destination_path"
 
