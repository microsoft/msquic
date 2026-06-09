# Publishing a Release

Follow these instructions to create and publish a new minor or patch version of MsQuic.

## Create a New Release Branch

A release branch will be created (forked) for each major/minor version of MsQuic.
It goes through a period of stabilization before the release is published.

1. Add (via PR) notes above for the new release.
1. Fork `main` branch to `release/X.Y` where `X` is the major version and `Y` is the minor version.
1. Update (via PR) the minor version for the `main` branch:
   - Run `./scripts/update-version.ps1 -Part Minor` to generate the relevant changes.
   - Also add the new version to the bug_report.yaml issue template file.

## Servicing a Release Branch

1. Changes first go into the `main` branch, and then are cherry-picked into the relevant `release/X.Y` branches.
1. Update (via PR) the patch version for the release branches:
   - Run `./scripts/update-version.ps1 -Part Patch` to generate the relevant changes.

## Publishing a Release Branch

1. Create a [new GitHub release](https://github.com/microsoft/msquic/releases/new) along with the corresponding tag.
   - Make sure to pick the correct `release/X.Y` branch
   - The tag should be the full version number: `vX.Y.Z`
   - The release title should be `MsQuic vX.Y.Z`
   - Put relevant information in the notes of the release (see previous releases for examples)
1. Wait for [msquic-Official-Tests](https://mscodehub.visualstudio.com/msquic/_build?definitionId=1824&_a=summary) pipeline to run for the newly created tag.
1. Download the `distribution` packages from the artifacts and upload them to the GitHub release:
   - msquic_gamecore_console_x64_Release_schannel.zip
   - msquic_linux_x64_Release_quictls.zip
   - msquic_linux_x64_Release_quictls_test.zip
   - msquic_windows_arm64_Release_quictls.zip
   - msquic_windows_arm64_Release_schannel.zip
   - msquic_windows_arm_Release_quictls.zip
   - msquic_windows_arm_Release_schannel.zip
   - msquic_windows_x64_Release_quictls.zip
   - msquic_windows_x64_Release_quictls_test.zip
   - msquic_windows_x64_Release_schannel.zip
   - msquic_windows_x64_Release_schannel_test.zip
   - msquic_windows_x86_Release_quictls.zip
   - msquic_windows_x86_Release_schannel.zip
1. Update (via PR) `main` branch's `test-down-level.yml` to point the newly uploaded `*_test.zip` release binaries.

> **Note** - NuGet packages are automatically published to nuget.org by the pipeline.

### Publishing Linux packages to packages.microsoft.com (PMC)

The publishing [pipeline](https://mscodehub.visualstudio.com/msquic/_build?definitionId=2068) automatically uploads packages into PMC when a tag is created.

Sometimes the pipeline fails due to PMC infra issues (e.g. the PMC HTTP endpoint returning errors). The publishing pipeline can be run manually to retry. When running manually, please ensure that the right tag is chosen and the right resources (under "Advanced options") are chosen. By default, the pipeline picks up the latest resources from the official build pipeline which are not always the right ones.

When testing the pipeline, please make sure to comment out the PMC cli commands in [upload-linux-packages.sh](https://github.com/microsoft/msquic/blob/main/scripts/upload-linux-packages.sh) to avoid accidentally publishing packages into prod.

### Publishing MsQuic for Alpine

Prerequisites:
- Docker
- Powershell

1. Checkout to release tag. (e.g. `git checkout v2.4.7`)
1. Run `generate-alpine-packaging-file.ps1` script from the repository root on host computer to create `APKBUILD` file for the release. (This script can run on any Linux distro, and this script will create a docker alpine container to calculate hash keys in APKBUILD file)
1. If you don't have account for [AlpineLinux GitLab](https://gitlab.alpinelinux.org). Create an account and [configure your SSH](https://docs.gitlab.com/ee/user/ssh.html).
1. If you didn't fork `aports` repository yet, Fork `https://gitlab.alpinelinux.org/alpine/aports`.
1. Clone `https://gitlab.alpinelinux.org/<your_username>/aports` repository.
1. Navigate to `aports/community/libmsquic` folder.
1. Replace the `APKBUILD` file with newly created `APKBUILD` file.
1. Create a commit using `community/libmsquic: upgrade to <version_number>` (version_number e.g. 2.5.0 or 2.4.4).
1. Create a merge request using `community/libmsquic: upgrade to <version_number>` (version_number e.g. 2.5.0 or 2.4.4).
1. Owners of the `aports` repository will respond to the PR or merge it in couple of days/hours.

For future reference: [Official documentation](https://wiki.alpinelinux.org/wiki/Creating_an_Alpine_package)

### Publishing the Rust Crate

The following are the complete (manual) steps for publishing the Rust crate.

1. Create a (Linux) GitHub CodeSpace.
1. `sudo apt update`
1. `sudo apt install curl`
1. `curl https://sh.rustup.rs -sSf | sh`
1. Restart bash.
1. `cargo login`
1. Create an API token on https://crates.io/settings/tokens (with `publish-update` scope).
1. Paste the token into bash.
1. If doing a beta release, update `Cargo.toml` to add a # after `beta` in the version.
1. `cargo publish` or `cargo publish --allow-dirty` if beta release

## Synchronizing with Windows

1. Once the release branch/tag is created, the undock pipeline should run automatically.
   - If for some reason there's a problem, you may need to run the pipeline manually by clicking on "Run Pipeline" [here](https://microsoft.visualstudio.com/undock/_build?definitionId=134439) (MSFT-only access required), scroll down to the **resources tab** and pick the MsQuic release tag of interest then run the pipeline.
   - Another workaround to force a manual re-run by going [here](https://microsoft.visualstudio.com/undock/_git/msquic/tags) (MSFT-only access required) and deleting the tag, and then waiting for the [mirror pipeline](https://microsoft.visualstudio.com/undock/_build?definitionId=134727) (MSFT-only access required) to run automatically re-copy over the tag from GitHub.
2. Once the pipeline passes tests, get the VPACK ID from the "Create VPACK" stage, and create a PR to point [this file](https://microsoft.visualstudio.com/OS/_git/os.2020?path=/minio/netio/quic/msquic/msquic.man) (MSFT-only access required) to the VPACK created by the pipeline run.
3. Review and merge the PR to complete the process.
