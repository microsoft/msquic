# Support for MsQuic

An MsQuic release begins its life in the main branch where it receives feature updates as well as servicing for security and bug fixes. When it is time to release, the code will be snapped into a release branch where it is stable and will only receive servicing for security and bug fixes.

## MsQuic Releases

MsQuic releases will correspond to Windows releases. A release branch will be created (forked) for each Windows release. The release branch will be created at the same time as in Windows: when we hit stabilization. Then, the release will be finalized some time before Windows GAs. Once finalized the release branch will only be serviced with security and bug fixes throughout its lifecycle, which will end at the same time as the Windows release support ends.

This table describes the version, release date and end of support for MsQuic releases.

| Version | Fork Date | Release Date | Support Type | End of Support |
| -- | -- | -- | -- | -- |
| 1.0 | Oct 1 2020 | TBD | TBD | TBD |

\* Future release dates are subject to change.

### MsQuic v1.0

MsQuic v1.0 is the first officially supported release. The primary shipping vehicle for this release will be the [Windows Server vNext](https://techcommunity.microsoft.com/t5/windows-server-insiders/announcing-windows-server-vnext-preview-build-19551/m-p/1133432) (actual name TBD) release. No official, signed binaries are currently slated to be released. Linux support is considered a preview for this release.

As the QUIC specifications have not yet been finalized (as of Aug 2020), it's likely only the latest draft version(s) numbers will be supported initially, and not the official "version 1". If the specs aren't RFC status at the release date, then the release will be serviced (updated) accordingly when they do reach RFC.

\* This information is still subject to change.

## MsQuic Branches

MsQuic has two types of branches **main** and **release** defined as:

* **Main** - Main is the primary development branch, and receives security and bug fixes just the same as the release branches. However, the main branch is where active development happens and because of this the main branch may experience breaking changes as we develop new features.

* **Release** - Release branches only receive security and bug fixes, and are considered stable. There should be no breaking changes in these branches, and they can be used for stable products.

\* Both types of branch receive critical fixes throughout their lifecycle, for security, reliability.

## Release Support Policies

MsQuic support lifecycle is governed by the Windows Server servicing channels: [LTSC and SAC](https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19)

* **LTSC** release branches will be serviced for 5 years mainstream and 5 years extended.
* **SAC** release branches will be serviced for 18 months.
* **Main** is not considered supported branch because it is under active development. It does however receive security and bug fixes.

### End of support

End of support refers to the date when Microsoft no longer provides fixes, updates, or online technical assistance for your product. As this date nears, make sure you have the latest available update installed. Without Microsoft support, you will no longer receive security updates that can help protect your machine from harmful viruses, spyware, and other malicious software that can steal your personal information.
