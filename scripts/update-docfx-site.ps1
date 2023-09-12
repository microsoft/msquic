$env:GIT_REDIRECT_STDERR = '2>&1'

# Checkout the Performance branch (where data and docfx is stored)
git checkout performance-dupe

# Commit the output file.
git config user.email "quicdev@microsoft.com"
git config user.name "QUIC Dev[bot]"
git add ./_site
git status
git commit -m "Update DocFx after documentation changes."
git pull
git push
