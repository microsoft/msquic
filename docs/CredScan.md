# Suppressing CredScan Warnings

When updating the openssl submodule, new tests or code may get flagged by
CredScan, and will need to be suppressed as it's 3rd party and we can't fix it.

These are the steps to silence the warnings:

1. Look at the `sdl_sources` results
2. Click on `1 artifact produced` and navigate to `drop_sdl_sources/sdl_sources`
3. Download the `.gdnsuppress` file
4. Copy the new warnings into `openssl.gdnsuppress`, sorting by the Target field
5. Commit the changes and ingest into Windows.

**Note** - You may also have to copy suppressions from other stages, similar to the process above.

### Regeneration from Scratch

To regenerate the `openssl.gdnsuppress` completely, create a temporary mscodehub PR that removes the `suppression:` `suppressionFile:` from `OneBranch.PullRequest.yml`.
Then follow the instructions above to get the new suppression file, but completely copy over the existing one instead.

> **TODO** - Perhaps we should automate the regeneration in a pipeline.
