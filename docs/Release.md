# Support for MsQuic

An MsQuic release begins its life in the main branch where it receives feature updates as well as servicing for security and bug fixes. When it is time to release, the code will be forked into a release branch where it is considered stable and will generally only receive servicing for security and bug fixes.

## MsQuic Branches

MsQuic has two main types of branches **main** and **release** defined as:

* **Main** - Main is the primary development branch, and receives security and bug fixes just the same as the release branches. However, the main branch is where active development happens and because of this the main branch may experience breaking changes as we develop new features.

* **Release** - Release branches only receive security and bug fixes, and are considered stable. There should be no breaking changes in these branches, and they can be used for stable products.

  * **Prerelease** - Only release branches explicitly indicated below, in the **Official Releases** section, are considered officially supported and serviced releases. All others are considered prereleases, which are considered stable, but will not receive servicing fixes.

\* Both main and official release branches receive critical fixes throughout their lifecycle, for security, reliability.

## Release Support Policies

MsQuic support lifecycle is governed by the Windows Server servicing channels: [LTSC and SAC](https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19)

* **LTSC** release branches will be serviced for 5 years mainstream and 5 years extended.
* **SAC** release branches will be serviced for 18 months.
* **Main** is not considered supported branch because it is under active development. It does however receive security and bug fixes.

## End of support

End of support refers to the date when Microsoft no longer provides fixes, updates, or online technical assistance for your product. As this date nears, make sure you have the latest available update installed. Without Microsoft support, you will no longer receive security updates that can help protect your machine from harmful viruses, spyware, and other malicious software that can steal your personal information.

# Official Releases

A release branch will be created (forked) for each official release of MsQuic. The release branch will then go through a several month stabilization process before it is then finalized as an official release. Once finalized the release branch will only be serviced with security and bug fixes throughout its lifecycle. MsQuic official releases generally will correspond to Windows releases, but in some cases additional future releases may be created for other major products. Releases for Windows generally will end support at the same time as the Windows release.

This table describes the version, release date and end of support for official (non-prerelease) MsQuic releases.

| Release | Branch | Fork Date | Release Date | Support Type | End of Support |
| -- | -- | -- | -- | -- | -- |
| [1.0](https://github.com/microsoft/msquic/releases/tag/v1.0.0-129524) | [release/1.0](https://github.com/microsoft/msquic/tree/release/1.0) | Nov 13 2020 | Jan 5 2021 | LTSC | Jan 4 2026 (2031) |
| [1.1](https://github.com/microsoft/msquic/releases/tag/v1.1.2) | [release/1.1](https://github.com/microsoft/msquic/tree/release/1.1) | Feb 10 2020 | TBD | TBD | TBD |

<br>\* Future **Release Dates** are subject to change.
<br>\** **End of Support** dates in parentheses are for [extended support](https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19#long-term-servicing-channel-ltsc).

## MsQuic v1.0

[MsQuic v1.0](https://github.com/microsoft/msquic/releases/tag/v1.0.0-129524) is the first officially supported release. The primary shipping vehicle for this release will be the Windows Server 2022 release. No official, signed binaries are currently slated to be released. Linux support is considered a preview for this release.

The QUIC specifications are currently "Submitted to IESG for Publication", so both the v1 and draft-29 versions are supported by this release.

> **Important** QUIC protocol features not fully implemented:
>
>  * 0-RTT
>  * Client-side Migration
>  * Server Preferred Address
>  * Path MTU Discovery

## MsQuic v1.1

[MsQuic v1.1](https://github.com/microsoft/msquic/releases/tag/v1.1.2) has various small improvements from v1.0. The primary shipping vehicle for this release will be the Windows Client (Cobalt) release. These changes include:

 - Preview support for [Version Negotiation](https://tools.ietf.org/html/draft-ietf-quic-version-negotiation-03) extension.
 - Public API header build fixes.
 - Improved certificate validation APIs.
 - OpenSSL certificate validation fixes.
 - Added (off by default) SSLKEYLOGFILE support.
 - Linux datapath bug fixes and improvements.
 - Various CI improvements around performance testing; including TCP comparison support.
 - Diagnostics documentation improvements.

The QUIC specifications have been approved by the IESG and are in RFC editor queue. Both the v1 and draft-29 versions are supported by this release.
