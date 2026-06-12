# MsQuic releases and support

MsQuic follows [semantic versioning](https://semver.org/).

## Releases

MsQuic releases are supported for a minimum of 18 months after release, and may be supported longer.
A new release is generally created every 6 months to a year.

**End of support** refers to the date when Microsoft no longer provides fixes, updates, or online technical assistance for your product.
As this date nears, make sure to upgrade to a supported version.

| Version | Branch                                                              | Fork Date   | Release Date | End of Support |
|---------|---------------------------------------------------------------------|-------------|--------------|----------------|
| v2.5    | [release/2.5](https://github.com/microsoft/msquic/tree/release/2.5) | May 15 2025 | May 16 2025  | TBD            |
| v2.4    | [release/2.4](https://github.com/microsoft/msquic/tree/release/2.4) | Aug 5 2024  | Aug 16 2024  | Sep 1 2026     |

### Historical versions

| Version | Branch                                                              | Fork Date   | Release Date | End of Support |
| v2.3    | [release/2.3](https://github.com/microsoft/msquic/tree/release/2.3) | Jan 26 2024 | Mar 12 2024  | Sep 12 2025    |

## Supported platforms

MsQuic officially supports the following operating systems and architectures.

| OS      | Architectures     |
|---------|-------------------|
| Windows | x64, arm64        |
| Linux   | x64, arm64, arm32 |

MsQuic may work on other platforms, including macOS, iOS, Android, x86, etc., but this is a best-effort basis with no support guarantee.

### Packages

**Windows user mode**

MsQuic is published as a NuGet package for Windows: [Microsoft.Native.Quic.MsQuic.Schannel](https://www.nuget.org/packages/microsoft.native.quic.msquic.schannel/).

A package using OpenSSL is also published: [Microsoft.Native.Quic.MsQuic.OpenSSL](https://www.nuget.org/packages/microsoft.native.quic.msquic.openssl/).

**Linux**

MsQuic packages are published on the [Microsoft Linux Software Repository](https://learn.microsoft.com/en-us/linux/packages).
The following distributions are supported:

| Distribution                                                                                        | Version                           | Architectures          |
|-----------------------------------------------------------------------------------------------------|-----------------------------------|------------------------|
| [Alpine](https://alpinelinux.org/)*                                                                 | 3.23, 3.22, 3.21                  | x86_64, aarch64, armv7 |
| [Amazon Linux](https://aws.amazon.com/linux/)                                                       | 2023                              | x86_64, aarch64        |
| [Azure Linux](https://github.com/microsoft/azurelinux)                                              | 3.0                               | x86_64, aarch64        |
| [CentOS Stream](https://www.centos.org/centos-stream/)                                              | 10                                | x86_64, aarch64        |
| [Debian](https://www.debian.org/)                                                                   | 13, 12                            | amd64, arm64, armhf    |
| [Fedora](https://fedoraproject.org/)                                                                | 43, 42                            | x86_64, aarch64, armhf |
| [openSUSE Leap](https://www.opensuse.org/)                                                          | 16, 15                            | x86_64, aarch64        |
| [Red Hat Enterprise Linux](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux) | 10, 9                             | x86_64, aarch64        |
| [SUSE Linux Enterprise Server](https://www.suse.com/products/server/)                               | 16, 15                            | x86_64, aarch64        |
| [Ubuntu](https://ubuntu.com/)                                                                       | 26.04, 25.10, 25.04, 24.04, 22.04 | amd64, arm64, armhf    |

\* Alpine packages are published in the Alpine [community repository](https://pkgs.alpinelinux.org/packages?name=libmsquic).

## MsQuic Branches

MsQuic has two main types of branches **main** and **release** defined as:

- **main** - Main is the primary development branch, and receives security and bug fixes just the same as the release branches. However, the main branch is where active development happens and it may experience breaking changes as we develop new features.
- **release/X.Y** - Release branches only receive security and bug fixes, and are considered stable.
