#!/bin/bash

# Exit on error
set -e

# Build the site
hugo
echo 'hexagram.foo' > gh-pages/CNAME
# Go into the output directory
cd gh-pages

# Initialize a new Git repo
git add .
git commit -m "Deploy site"

# Push to gh-pages
git push -f origin gh-pages

# Clean up
cd ..
rm -rf gh-pages/.git

echo "✅ Deployed to gh-pages branch"

