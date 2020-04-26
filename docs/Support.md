# Support for MsQuic

An MsQuic release begins its life in the master branch where it receives feature updates as well as servicing for security and bug fixes. When it is time to release, the code will be snapped into a release branch where it is stable and will only receive servicing for security and bug fixes. 

## MsQuic Releases

MsQuic releases will correspond to Windows releases. A release branch will be created for each Windows release. The release branch will be created at the same time as in Windows: when we hit stabilization. Then, the release will be finalized some time before Windows GAs. Once finalized the release branch will only be serviced with security and bug fixes throughout its lifecycle, which will end at the same time as the Windows release support ends.

This table describes the version, release date and end of support for MsQuic releases.

|  Version  |  Release Date | Support Type | End of Support |
| -- | -- | -- | -- |
| [MsQuic 1.0](https://techcommunity.microsoft.com/t5/networking-blog/bg-p/NetworkingBlog) | TBD | SAC | TBD |

\* Future release dates are subject to change.

## MsQuic Branches

MsQuic has two types of branches **master** and **release** defined as:

* **Master** - The master branch receives security and bug fixes just the same as the release branches. However, the master branch is where active development happens and because of this the master branch may experience breaking changes as we develop new features. 

* **Release** - Release branches only receive security and bug fixes, and are considered stable. There should be no breaking changes in these branches, and they can be used for stable products.

\* Both types of branch receive critical fixes throughout their lifecycle, for security, reliability.

## Release Support Policies

MsQuic support lifecycle is governed by the Windows Server servicing channels: [LTSC and SAC](https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19)

* **LTSC** release branches will be serviced for 5 years mainstream and 5 years extended.
* **SAC** release branches will be serviced for 18 months.
* **Master** is not considered supported branch because it is under active development. It does however receive security and bug fixes.

### End of support

End of support refers to the date when Microsoft no longer provides fixes, updates, or online technical assistance for your product. As this date nears, make sure you have the latest available update installed. Without Microsoft support, you will no longer receive security updates that can help protect your machine from harmful viruses, spyware, and other malicious software that can steal your personal information.
