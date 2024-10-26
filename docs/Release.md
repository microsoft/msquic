# Support for MsQuic

An MsQuic release begins its life in the main branch where it receives feature updates as well as servicing for security and bug fixes. When it is time to release, the code will be forked into a release branch where it is considered stable and will generally only receive servicing for security and bug fixes.

## MsQuic Branches

MsQuic has two main types of branches **main** and **release** defined as:

* **Main** - Main is the primary development branch, and receives security and bug fixes just the same as the release branches. However, the main branch is where active development happens and because of this the main branch may experience breaking changes as we develop new features.

* **Release** - Release branches only receive security and bug fixes, and are considered stable. There should be no breaking changes in these branches, and they can be used for stable products.

  * **Prerelease** - The [Releases](Release.md#releases) section below indicates which releases are considered officially supported and serviced releases. All others are considered prereleases, which are generally considered stable, but will **not receive servicing fixes**.

\* Both main and official release branches receive critical fixes throughout their lifecycle, for security, reliability.

## Release Support Policies

MsQuic support lifecycle is governed by the Windows Server servicing channels: [LTSC and SAC](https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19)

* **LTSC** indicates official release branches to be serviced for 5 years mainstream and 5 years extended.
* **SAC** indicates official release branches to be serviced for 18 months.
* **PRE** indicates prerelease branches (**not** officially supported).
* **TBD** indicates release branches that are set to be classified as one of the above.

> **Important** Main is not considered **officially supported**. It is under active development (i.e. not stable), however it does receive security and bug fixes.

## End of support

End of support refers to the date when Microsoft no longer provides fixes, updates, or online technical assistance for your product. As this date nears, make sure you have the latest available update installed. Without Microsoft support, you will no longer receive security updates that can help protect your machine from harmful viruses, spyware, and other malicious software that can steal your personal information.

# Releases

A release branch will be created (forked) for each release of MsQuic. Official release branches will then go through a several month stabilization process before it is then finalized. Once finalized, offical release branches will only be serviced with security and bug fixes throughout its lifecycle. MsQuic official releases generally will correspond to Windows releases, but in some cases additional future releases may be created for other major products. Official releases for Windows generally will end support at the same time as the Windows release.

This table describes all officially supported MsQuic releases.

| [Type](Release.md#release-support-policies) | Branch | Consumer | Fork Date | Release Date | End of Support | Supported Platforms |
| -- | -- | -- | -- | -- | -- | -- |
| SAC | [release/2.2](https://github.com/microsoft/msquic/tree/release/2.2) | [Windows Server 2022](https://docs.microsoft.com/en-us/windows/release-health/status-windows-server-2022)<br>[Windows 11](https://www.microsoft.com/software-download/windows11) | Apr 18 2023 | June 1 2023 | Dec 1 2024 | Windows, Linux |
| SAC | [release/2.3](https://github.com/microsoft/msquic/tree/release/2.3) | [Windows Server 2025](https://techcommunity.microsoft.com/t5/windows-server-news-and-best/introducing-windows-server-2025/ba-p/4026374)<br>[Windows 11](https://www.microsoft.com/software-download/windows11) | Jan 26 2024 | Mar 12 2024 | Sept 12 2025 | Windows, Linux |
| SAC | [release/2.4](https://github.com/microsoft/msquic/tree/release/2.4) | [Windows Server 2025](https://techcommunity.microsoft.com/t5/windows-server-news-and-best/introducing-windows-server-2025/ba-p/4026374)<br>[Windows 11](https://www.microsoft.com/software-download/windows11)<br>[.NET 9.0](https://dotnet.microsoft.com/en-us/download/dotnet/9.0) | Aug 5 2024 | Aug 16 2024 | Feb 16 2026 | Windows, Linux |

<br>\* Future **Release Dates** are subject to change.
<br>\** **End of Support** dates do not include possible [extended support](https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19#long-term-servicing-channel-ltsc) extensions.

# Publishing a Release

## Create a New Release Branch

1. Add (via PR) notes above for the new release.
1. Fork `main` branch to `release/X.Y` where `X` is the major version and `Y` is the minor version.
1. Update (via PR) the minor version for the `main` branch:
   - Run `./scripts/update-version.ps1 -Part Minor` to generate the relavent changes.
   - Also add the new version to the bug_report.yaml issue template file.

## Servicing a Release Branch

1. Changes first go into the `main` branch, and then are cherry-picked into the relavent `release/X.Y` branches.
1. Update (via PR) the patch version for the release branches:
   - Run `./scripts/update-version.ps1 -Part Patch` to generate the relavent changes.

## Publishing a Release Branch

1. Create a [new GitHub release](https://github.com/microsoft/msquic/releases/new) along with the corresponding tag.
   - Make sure to pick the correct `release/X.Y` branch
   - The tag should be the full version number: `vX.Y.Z`
   - The release title should be `MsQuic vX.Y.Z`
   - Put relavent information in the notes of the release (see previous releases for examples)
1. Wait for [msquic-Official-Tests](https://mscodehub.visualstudio.com/msquic/_build?definitionId=1824&_a=summary) pipeline to run for the newly created tag.
1. Download the `distribution` packages from the artifacts and upload them to the GitHub release:
   - msquic_gamecore_console_x64_Release_schannel.zip
   - msquic_linux_x64_Release_openssl.zip
   - msquic_linux_x64_Release_openssl_test.zip
   - msquic_linux_x64_Release_openssl3.zip
   - msquic_linux_x64_Release_openssl3_test.zip
   - msquic_windows_arm64_Release_openssl3.zip
   - msquic_windows_arm64_Release_schannel.zip
   - msquic_windows_arm_Release_openssl.zip
   - msquic_windows_arm_Release_openssl3.zip
   - msquic_windows_arm_Release_schannel.zip
   - msquic_windows_x64_Release_openssl.zip
   - msquic_windows_x64_Release_openssl_test.zip
   - msquic_windows_x64_Release_openssl3.zip
   - msquic_windows_x64_Release_openssl3_test.zip
   - msquic_windows_x64_Release_schannel.zip
   - msquic_windows_x64_Release_schannel_test.zip
   - msquic_windows_x86_Release_openssl.zip
   - msquic_windows_x86_Release_openssl3.zip
   - msquic_windows_x86_Release_schannel.zip
1. From Linux (use GitHub Codespace) to publish the latest Rust Crate. (CURRENTLY BROKEN)
   - Run `cargo publish` from the `release/X.Y` branch.
1. Update (via PR) `main` branch's `test-down-level.yml` to point the newly uploaded `*_test.zip` release binaries.

> **Note** - NuGet packages are automatically published to nuget.org by the pipeline.

### Publishing Linux packages to packages.microsoft.com (PMC)

The publishing [pipeline](https://mscodehub.visualstudio.com/msquic/_build?definitionId=2068) automatically uploads packages into PMC when a tag is created.

Sometimes the pipeline fails due to PMC infra issues (e.g. the PMC HTTP endpoint returning errors). The publishing pipeline can be run manually to retry. When running manually, please ensure that the right tag is chosen and the right resources (under "Advanced options") are chosen. By default, the pipeline picks up the latest resources from the official build pipeline which are not always the right ones.

When testing the pipeline, please make sure to comment out the PMC cli commands in [upload-linux-packages.sh](https://github.com/microsoft/msquic/blob/main/scripts/upload-linux-packages.sh) to avoid accidentally publishing packages into prod.

### Publishing MsQuic for Alpine

Prerequisites:
- Docker

1. Run `generate-alpine-packaging-file.ps1` script on host computer to create `APKBUILD` file for the release. (This script can run on any Linux distro, and this script will create a docker alpine container to calculate hash keys in APKBUILD file)
1. If you don't have account for [AlpineLinux GitLab](https://gitlab.alpinelinux.org). Create an account and [configure your SSH](https://docs.gitlab.com/ee/user/ssh.html).
1. If you didn't fork `aports` repository yet, Fork `https://gitlab.alpinelinux.org/alpine/aports`.
1. Clone `https://gitlab.alpinelinux.org/<your_username>/aports` repository.
1. Navigate to `aports/community/libmsquic` folder.
1. Replace the `APKBUILD` file with newly created `APKBUILD` file.
1. Create a commit using `community/libmsquic: upgrade to <version_number>` (version_number e.g. 2.5.0 or 2.4.4).
1. Create a merge request using `community/libmsquic: upgrade to <version_number>` (version_number e.g. 2.5.0 or 2.4.4).
1. Owners of the `aports` repository will respond to the PR or merge it in couple of days/hours.

For future reference: [Official documentation](https://wiki.alpinelinux.org/wiki/Creating_an_Alpine_package)

## Synchronizing with Windows

1. Once the release branch is created, set the pipeline [here](https://mscodehub.visualstudio.com/msquic/_build?definitionId=1868) to ingest the release branch into Windows, and run it.
2. When the pipeline passes tests, it'll create a PR.
3. Review and merge the PR to complete the process.
