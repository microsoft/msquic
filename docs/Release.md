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
| LTSC | [release/1.0](https://github.com/microsoft/msquic/tree/release/1.0) | [Server 2022](https://docs.microsoft.com/en-us/windows/release-health/status-windows-server-2022) | Nov 13 2020 | Jan 5 2021 | Jan 4 2026 |
| SAC | [release/1.1](https://github.com/microsoft/msquic/tree/release/1.1) | Windows 11 | Feb 10 2021 | Oct 5 2021 | Apr 5 2023 |
| PRE | [prerelease/1.2](https://github.com/microsoft/msquic/tree/prerelease/1.2) | N/A | Mar 26 2021 | N/A | N/A |
| PRE | [prerelease/1.3](https://github.com/microsoft/msquic/tree/prerelease/1.3) | N/A | Apr 27 2021 | N/A | N/A |
| PRE | [prerelease/1.4](https://github.com/microsoft/msquic/tree/prerelease/1.4) | N/A | Jun 1 2021 | N/A | N/A |
| PRE | [prerelease/1.5](https://github.com/microsoft/msquic/tree/prerelease/1.5) | N/A | Jul 16 2021 | N/A | N/A |
| PRE | [prerelease/1.6](https://github.com/microsoft/msquic/tree/prerelease/1.6) | N/A | Jul 28 2021 | N/A | N/A |
| PRE | [prerelease/1.7](https://github.com/microsoft/msquic/tree/prerelease/1.7) | N/A | Aug 13 2021 | N/A | N/A |
| PRE | [prerelease/1.8](https://github.com/microsoft/msquic/tree/prerelease/1.8) | N/A | Sep 13 2021 | N/A | N/A |
| PRE | [prerelease/1.9](https://github.com/microsoft/msquic/tree/prerelease/1.9) | N/A | Oct 20 2021 | N/A | N/A |
| SAC | [release/2.0](https://github.com/microsoft/msquic/tree/release/2.0) | Client | Mar 1 2022 | May 1 2022 | Nov 1 2023 |

<br>\* Future **Release Dates** are subject to change.
<br>\** **End of Support** dates do not include possible [extended support](https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19#long-term-servicing-channel-ltsc) extensions.

## MsQuic v1.0 (LTSC)

[MsQuic v1.0](https://github.com/microsoft/msquic/releases/tag/v1.0.0-129524) is the first officially supported release. The primary shipping vehicle for this release will be the [Windows Server 2022](https://docs.microsoft.com/en-us/windows/release-health/status-windows-server-2022) release. No official, signed binaries are currently slated to be released. Linux support is considered a preview for this release.

The QUIC specifications are currently "Submitted to IESG for Publication", so both the v1 and draft-29 versions are supported by this release.

> **Important** QUIC protocol features not fully implemented:
>
>  * 0-RTT
>  * Client-side Migration
>  * Server Preferred Address
>  * Path MTU Discovery

### Known Issues

- `GetParam` for `QUIC_PARAM_CONN_STATISTICS` does not populate `Handshake.*` fields.

## MsQuic v1.1 (SAC)

[MsQuic v1.1](https://github.com/microsoft/msquic/releases/tag/v1.1.3) has various small improvements from v1.0. The primary shipping vehicle for this release will be the [Windows 11](https://blogs.windows.com/windowsexperience/2021/08/31/windows-11-available-on-october-5/) client release. These changes include:

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

## MsQuic v1.5 (Prerelease)

**Not officially supported**

[MsQuic v1.5](https://github.com/microsoft/msquic/releases/tag/v1.5.0) is a prerelease so there is no expected shipping vehicle. Some noted changes in this release include:

- Windows Kernel client certificate support (#1652).
- Added load balancer app (#1696) and automated testing (#1707).
- Fixed a bug for QUIC_SETTING size validation logic (#1724).
- Added support for local UDP port sharing (Linux only) (#1751).
- Switched Param Id's to not be overlapping (#1758).
- Refactored library load (#1748) and added static linking support (Windows only) (#1446).
- Fixed bug around handshake idle timeout (#1780).
- Added support for stream prioritization (#1778).
- Fixed bug when shutting connection down during the handshake (#1797).
- Improved testing around path changes and few minor bug fixes (#1783, #1801).
- Improved event callback reentrancy to reduce app complexity (#1802).
- Fixed bug related to sharing abort code for stream send/recv shutdown (#1809).
- Fixed bug related to queuing 0-RTT during the handshake (but after start) (#1817).
- Use root level certificate verification callback in OpenSSL (#1818).
- Ignore Duplicate Stream Read Shutdowns (#1822).
- Constrain processor index to processor count on posix (#1824).
- Build speed and build dependency improvements (#1845) (#1839).
- Initial support for Android binaries (#1835).
- Update version negotiation to draft v4 (#1826).
- Fix issues where datapaths and sockets might be used incorrectly (#1843) (#1837).
- Various documentation improvements and additions.

Official (v1) RFC and draft-29 are supported by this release.

## MsQuic v1.6 (Prerelease)

**Not officially supported**

[MsQuic v1.6](https://github.com/microsoft/msquic/releases/tag/v1.6.0) is a prerelease so there is no expected shipping vehicle. Some noted changes in this release include:

- Support ConnectionClose calls in NEW_CONNECTION Event (#1849).
- Some Linux packaging fixes (#1852) and build fixes (#1855).
- Support Setting Local Interface Index (#1804) on Windows.
- Fix issue with no certificate validation set on client certificate (#1728).

Official (v1) RFC and draft-29 are supported by this release.

## MsQuic v1.7 (Prerelease)

**Not officially supported**

[MsQuic v1.7](https://github.com/microsoft/msquic/releases/tag/v1.7.0) is a prerelease so there is no expected shipping vehicle. Some noted changes in this release include:

- Enable Spectre mitigations and CFG for windows user mode (#1854).
- Add support for tracing owning process in kernel mode (#1865).
- Release binaries are now signed (#1869) (#1879).
- Return ABORTED rather than INVALID_STATE if stream opened or started after remote close (#1875).
- Fix potential spin loop during send if there is not enough room to send (#1886).
- Support building posix without sendmmsg (#1896).
- Use larger batch size if send segmentation is not available in posix (#1897).
- Fix library version being set in incorrect location (#1905).

Official (v1) RFC and draft-29 are supported by this release.

## MsQuic v1.8 (Prerelease)

**Not officially supported**

[MsQuic v1.8](https://github.com/microsoft/msquic/releases/tag/v1.8.0) is a prerelease so there is no expected shipping vehicle. Signed Windows binaries are available. Some noted changes in this release include:

- Update OpenSSL to v1.1.1l (#1936).
- Add support for client certificates with OpenSSL (#1930).
- Bug fix for race condition around stateless operations and binding initialization (#1928).
- Bug fix for NULL pointer read in stateless retry scenario (#1951).
- Bug fix for path changes incorrectly resetting CC's bytes in flight (#1976).
- Refactor CC to support multiple algorithms (#1949).
- Various fixes for packaging automation (#1915, #1916, #1921, #1939, #1961).
- Improvements in memory calculations for posix platforms (#1928).
- Use inbox certificate validation for macOS/iOS (#1925).
- Build macOS/iOS framework bundles (#1927).
- Enable macOS core dump collection in automation (#1969).
- Xbox GameCore build support (#1947).
- Various test code fixes (#1970, #1974).

Official (v1) RFC and draft-29 are supported by this release.

## MsQuic v1.9 (Prerelease)

**Not officially supported**

[MsQuic v1.9](https://github.com/microsoft/msquic/releases/tag/v1.9.0) is a prerelease so there is no expected shipping vehicle. Signed Windows binaries are available. Some noted changes in this release include:

- Xbox GameCore Support (#1973, #2005, #2084)
- Adds performance counters around path changes (#1990)
- Bug Fix: Fix shutdown bug by cleaning up all sends (#1850)
- Additional connetion event documentation (#1996)
- Add UWP nuget package support (#2002)
- Improve client certificate validation (#1966)
- Support non-RSA keys in OpenSSL-CAPI abstraction (#2000)
- Bug Fix: Fix stream abort bug (#2049)
- Bug Fix: Fix connection FC handling on stream abort (#2070)
- Bug Fix: Fix rare endless loop in send path (#2082)

Official (v1) RFC and draft-29 are supported by this release.

## MsQuic v2.0 (SAC)

[MsQuic v2.0](https://github.com/microsoft/msquic/releases/tag/v2.0.1) is an official release. Signed Windows binaries and [NuGet packages](https://www.nuget.org/profiles/msquic) are available. Signed Linux package are also available.

Official (v1) RFC and draft-29 are supported by this release.

### Breaking Changes

- Fix QUIC_SETTINGS across different versions (#2271)
- Remove synchronous StreamStart (#2312)
- Remove Level from SetParam/GetParam (#2322)
- Add new datagram send state enum (#2342)
- Add support for async listener stop (#2346)
- Refactor custom CID prefix (#2363)
- Make StreamReceiveComplete not fail (#2371)

#### Upgrade Notes

The following changes will be necessary for apps that upgrade from v1.* to v2.0:

- Remove any usage of `QUIC_STREAM_START_FLAG_ASYNC`, replacing with `QUIC_STREAM_START_FLAG_NONE` if no other flags are used. If the flag was not used before, the app code must handle the call not blocking any more.
- Remove all `Level` parameters passed to `GetParam` or `SetParam`.
- Ensure the app handles `ListenerStop` not blocking any more. `ListenerClose` still blocks.
- No more need to check for a return code from `StreamReceiveComplete`.
- QUIC_ADDRESS_FAMILY_IPV6 has been changed to be platform specific rather then always windows values. For C/C++ consumers this is only a binary breaking change. For Interop consumers, the value will change for linux and macOS.

### Other Changes

- Various Linux build and packaging improvements (#2090, #2092, #2097)
- Various OpenSSL improvements and refactoring (#2098, #2083, #2111, #2154)
- Various certificate handling improvements and refactoring (#2155, #2158, #2160, #2164)
- Mirroring and OneBranch build infrastructure improvements (#2093, #2097, #2125, #2127, #2128, #2129)
- Datapath refactoring for low latency work (#2107, #2122, #2130, #2132, #2134, #2161, #2168)
- Various WAN perf improvements (#2266, #2269, #2270, #2296, #2304, #2309, #2343)
- Updates for ACK Frequency Draft-2 (#2347)
- Performance tool improvements (#2110, #2113, #2166)
- Visual Studio 2022 support (#2119)
- Interop layers for Rust and C# (#1832, #2100, #1917)
- Update OpenSSL to 1.1.1m (#2229)
- Various documentation improvements
- Added scorecard and dependabot support (#2310)
- Fix macOS datapath asserting in an initialization race (#2398)
- Add QUIC_STATISTICS_V2 parameter (#2386)
