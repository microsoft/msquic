# Define the custom link to replace "../src"
$customLink = "https://github.com/microsoft/msquic/tree/main/src"

# Get the directory of markdown files from the user input
$dir = "./docs"

# Get all the markdown files in the directory
$files = Get-ChildItem -Path $dir -Filter *.md

# Loop through each file
foreach ($file in $files) {
    # Read the file content as a string
    $content = Get-Content -Path $file.FullName -Raw

    # Replace all occurrences of "../src" with the custom link
    $content = $content -replace "\.\./src", $customLink

    # Write the modified content back to the file
    Set-Content -Path $file.FullName -Value $content
}

# Write a message to indicate the completion of the task
Write-Host "All done!"
