$jsonContent = @"
{
  "metadata": [
    {
      "src": [
        {
          "files": [
            "bin/**/*.dll"
          ]
        }
      ],
      "dest": "api",
      "includePrivateMembers": false,
      "disableGitFeatures": false,
      "disableDefaultFilter": false,
      "noRestore": false,
      "namespaceLayout": "flattened",
      "memberLayout": "samePage",
      "EnumSortOrder": "alphabetic",
      "allowCompilationErrors": false
    }
  ],
  "build": {
    "content": [
      {
        "files": [ "**/*.{md,yml}" ],
        "exclude": [ "_site/**", "obj/**" ]
      }
    ],
    "resource": [
      {
        "files": [ "**/images/**", "codesnippet/**" ],
        "exclude": [ "_site/**", "obj/**" ]
      }
    ],
    "output": "_site",
    "globalMetadataFiles": [],
    "fileMetadataFiles": [],
    "template": [
      "default",
      "modern"
    ],
    "postProcessors": ["ExtractSearchIndex"],
    "keepFileLink": false,
    "disableGitFeatures": false
  }
}
"@

$jsonContent | Out-File -FilePath "docfx.json"
Write-Host "docfx.json file has been created with the specified contents."

$yamlContent = @"
- name: MsQuic
  href: docs/

- name: API
  href: docs/api/
"@

$yamlContent | Out-File -FilePath "toc.yml"
Write-Host "toc.yml file has been created with the specified contents."

$indexMdContent = @"
# MsQuic Documentation With DocFx:

## Why?

A Better Search Experience.

Taking Advantage of built-in indexing offered by DocFx,
and the nice UI configuration options (light / dark) mode,
makes debugging a little less painful.

Try out the search feature!

Try out dark mode!

Chatbot coming soon!
"@

$indexMdContent | Out-File -FilePath "index.md"
Write-Host "index.md file has been created with the specified contents."
