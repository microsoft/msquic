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

> **Important** Main and prerelease branches are considered not **officially supported**.
>  * Prerelease branches get no further changes.
>  * Main is under active development (i.e. not stable), however it does receive security and bug fixes.

## End of support

End of support refers to the date when Microsoft no longer provides fixes, updates, or online technical assistance for your product. As this date nears, make sure you have the latest available update installed. Without Microsoft support, you will no longer receive security updates that can help protect your machine from harmful viruses, spyware, and other malicious software that can steal your personal information.

# Releases

A release branch will be created (forked) for each release of MsQuic. Official release branches will then go through a several month stabilization process before it is then finalized. Once finalized, offical release branches will only be serviced with security and bug fixes throughout its lifecycle. MsQuic official releases generally will correspond to Windows releases, but in some cases additional future releases may be created for other major products. Official releases for Windows generally will end support at the same time as the Windows release.

This table describes all MsQuic releases, both officially supported (LTSC or SAC) and unsupported (PRE).

| [Type](Release.md#release-support-policies) | Branch | Windows | Fork Date | Release Date | End of Support |
| -- | -- | -- | -- | -- | -- |
| LTSC | [release/1.0](https://github.com/microsoft/msquic/tree/release/1.0) | Server 2022 | Nov 13 2020 | Jan 5 2021 | Jan 4 2026 |
| TBD | [release/1.1](https://github.com/microsoft/msquic/tree/release/1.1) | TBD | Feb 10 2021 | TBD | TBD |
| PRE | [prerelease/1.2](https://github.com/microsoft/msquic/tree/prerelease/1.2) | N/A | Mar 26 2021 | N/A |N/A |
| PRE | [prerelease/1.3](https://github.com/microsoft/msquic/tree/prerelease/1.3) | N/A | Apr 27 2021 | N/A |N/A |
| PRE | [prerelease/1.4](https://github.com/microsoft/msquic/tree/prerelease/1.4) | N/A | Jun 1 2021 | N/A |N/A |

<br>\* Future **Release Dates** are subject to change.
<br>\** **End of Support** dates do not include possible [extended support](https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19#long-term-servicing-channel-ltsc) extensions.

## MsQuic v1.0 (LTSC)

[MsQuic v1.0](https://github.com/microsoft/msquic/releases/tag/v1.0.0-129524) is the first officially supported release. The primary shipping vehicle for this release will be the Windows Server 2022 release. No official, signed binaries are currently slated to be released. Linux support is considered a preview for this release.

The QUIC specifications are currently "Submitted to IESG for Publication", so both the v1 and draft-29 versions are supported by this release.

> **Important** QUIC protocol features not fully implemented:
>
>  * 0-RTT
>  * Client-side Migration
>  * Server Preferred Address
>  * Path MTU Discovery

### Known Issues

- `GetParam` for `QUIC_PARAM_CONN_STATISTICS` does not populate `Handshake.*` fields.

## MsQuic v1.1 (TBD)

[MsQuic v1.1](https://github.com/microsoft/msquic/releases/tag/v1.1.2) has various small improvements from v1.0. The primary shipping vehicle for this release will be the Windows Client (official name TBD) release. These changes include:

 - Preview support for [Version Negotiation](https://tools.ietf.org/html/draft-ietf-quic-version-negotiation-03) extension.
 - Public API header build fixes.
 - Improved certificate validation APIs.
 - OpenSSL certificate validation fixes.
 - Added (off by default) SSLKEYLOGFILE support.
 - Linux datapath bug fixes and improvements.
 - Various CI improvements around performance testing; including TCP comparison support.
 - Diagnostics documentation improvements.

The QUIC specifications have been approved by the IESG and are in RFC editor queue. Both the v1 and draft-29 versions are supported by this release.

### Known Issues

- `GetParam` for `QUIC_PARAM_CONN_STATISTICS` does not populate `Handshake.*` fields.

## MsQuic v1.2 (Prerelease)

**Not officially supported**

[MsQuic v1.2](https://github.com/microsoft/msquic/releases/tag/v1.2.0) has numerous improvements from v1.1. As this is a prerelease, there is no expected shipping vehicle for this release. Some noted changes in this release include:

- Switched to quictls (https://github.com/quictls/openssl) and the 1.1.1 branch of OpenSSL instead of 3.0
- Initial MacOS support added (using OpenSSL)
- Support for RSS, GSO and Receive Batching on Linux
- Initial OpenSSL session resumption and 0-RTT support
- Improved CPU and WAN performance
- Various API improvements (e.g. new delayed send API flag; query handshake info)
- Initial client certificate support with Schannel on Windows
- Initial support for ACK frequency (or delayed ACK) QUIC extension
- Support for pkcs12 imports

The QUIC specifications are still in RFC editor queue. Both the v1 and draft-29 versions are still supported by this release.

## MsQuic v1.3 (Prerelease)

**Not officially supported**

[MsQuic v1.3](https://github.com/microsoft/msquic/releases/tag/v1.3.0) has numerous improvements from v1.2. As this is a prerelease, there is no expected shipping vehicle for this release. Some noted changes in this release include:

- Removed old/unused `mitls` and `stub` TLS providers. Only `schannel` and `openssl` are officially supported (#1398, #1411).
- Fully support Resumption and 0-RTT with OpenSSL (#1469).
- Fully support Windows UWP apps (#1429, #1452, #1454).
- Support Client certificate validation (#1366).
- Support ChaCha20-Poly1305 with OpenSSL (#1431).
- Support Cipher Suite allow-list (#1430).
- Support Portable Certificate verification (#1450).
- Various performance improvements (tune recv pkt queue, worker partition ID for send, UDP send queuing) (#1424, #1448, #1451, #1456, #1474, #1483).
- Fixed SO_REUSEPORT perf issue on server sockets (Linux only) (#1391).
- Fixed various issues with macOS (arm platform detection, max CPU count) (#1388, #1427).
- Fixes bugs that causes stream to get in (temporary) bad state when aborting receive path (#1513, #1516).
- Update `StreamShutdown` to run inline on callbacks (#1521).
- Support universal binaries for macOS (#1414).
- Added/updated documentation, especially around trouble shooting (#1423, #1467, #1481, #1486).
- Refactored/improved WPA plugin and cmd line tool, QuicTrace (#1482, #1484, #1485, #1490, #1493, #1499).

The QUIC specifications are being actively looked at by the RFC editor. Both the v1 and draft-29 versions are still supported by this release.

## MsQuic v1.4 (Prerelease)

**Not officially supported**

[MsQuic v1.4](https://github.com/microsoft/msquic/releases/tag/v1.4.0) has numerous improvements from v1.3. As this is a prerelease, there is no expected shipping vehicle for this release. Some noted changes in this release include:

- Updated User Mode PGO.
- Perf improvement from sent packet metadata stream ref counting (#1529).
- Support address sanitizer on Windows.
- Random allocation test support for SpinQuic and BVT (#1537, #1541).
- Fix key phase and key update detection logic (#1548).
- Fixed bug with stateless reset and retired CIDs (#1568).
- Add support for Peer Accept Stream event (#1560).
- Various bug fixes found from random allocation failure tests.
- Various additional test cases added.
- Added multiple API version support.
- Lots of improved documentation.
- Enabled ACK frequency in CPU limited scenarios (#1588).
- Support for DPLPMTUD (#1563).
- Reduced min MTU to 1248 (#1673).
- Refactored POSIX error codes (breaking change for POSIX, #1645).

The QUIC specifications now offically RFC. Both the v1 and draft-29 versions are still supported by this release.
