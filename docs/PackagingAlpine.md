# Packaging MsQuic for Alpine

1. Create release and create tag with exact version number (e.g. v2.5.0).
2. Run `generate-alpine-packaging-file.ps1` script to create `APKBUILD` file for the release. (This script can run on any Linux distro.)
3. If you don't have account for [AlpineLinux GitLab](https://gitlab.alpinelinux.org). Create an account and [configure your SSH](https://docs.gitlab.com/ee/user/ssh.html).
4. If you didn't fork `aports` repository yet, Fork `https://gitlab.alpinelinux.org/alpine/aports`.
5. Clone `https://gitlab.alpinelinux.org/<your_username>/aports` repository.
6. Navigate to `aports/testing/libmsquic` folder.
7. Replace the `APKBUILD` file with newly created `APKBUILD` file.
8. Create a commit using `testing/libmsquic: upgrade to <version_number>` (version_number e.g. 2.5.0 or 2.4.4).
9. Create a merge request using `testing/libmsquic: upgrade to <version_number>` (version_number e.g. 2.5.0 or 2.4.4).
10. Owners of the `aports` repository will respond to the PR or merge it in couple of days/hours.

For future reference: [Official documentation](https://wiki.alpinelinux.org/wiki/Creating_an_Alpine_package)
