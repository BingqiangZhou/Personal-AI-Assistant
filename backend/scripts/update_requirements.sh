#!/bin/bash
# Update requirements.txt from pyproject.toml
# This script regenerates requirements.txt based on pyproject.toml dependencies

set -e

echo "🔄 Regenerating requirements.txt from pyproject.toml..."

# Generate requirements.txt without header (we'll add our own)
uv pip compile pyproject.toml -o requirements-temp.txt --no-header

# Add informative header
cat > requirements.txt << 'EOF'
# This file is auto-generated from pyproject.toml using 'uv pip compile'
# DO NOT EDIT MANUALLY - Use 'uv add/remove' to manage dependencies
# To regenerate: Run ./scripts/update_requirements.sh

EOF

# Append the compiled requirements
cat requirements-temp.txt >> requirements.txt

# Remove temporary file
rm requirements-temp.txt

echo "✅ requirements.txt has been updated successfully!"
echo "📋 Total packages: $(grep -c '^[a-z]' requirements.txt)"
