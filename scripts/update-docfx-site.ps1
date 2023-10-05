$env:GIT_REDIRECT_STDERR = '2>&1'

# Checkout the Performance branch (where data and docfx is stored)
git fetch
# Stash any changes to the current branch
git stash
git checkout performance

# Commit the output file.
git config user.email "quicdev@microsoft.com"
git config user.name "QUIC Dev[bot]"

$folderPath = "./msquicdocs"
if (Test-Path $folderPath) {
    Remove-Item $folderPath -Recurse -Force
}

mv ./_site ./msquicdocs
git add ./msquicdocs
git status
git commit -m "Update DocFx after documentation changes."
git pull
git push
