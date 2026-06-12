# Publishing a Release

Follow the instructions below to create, validate and publish a new minor or patch version of MsQuic.

## Creating a new minor release

When publishing a new minor release, the main branch is forked into a new release branch.
The documentation and scripts must be updated in the `main` branch.
The rest of the process is similar to creating a patch release.

1. **Update the Release Documentation**
   Create a PR against `main` to update the release table in [Release.md](../Release.md).

2. **Create the Release Branch**
   Fork the main branch to create release/X.Y:
   ```
   git checkout main
   git pull
   git checkout -b release/X.Y
   git push
   ```
3. **Bump the Version on main**
   After creating the release branch, increment the minor version on main:
   ```
   ./scripts/update-version.ps1 -Part Minor
   ```

This updates the version number across all relevant files, so that main is ready for the next release.
A branch should always have the version number for its next release.

> **Tip**: The [create-release.ps1](/scripts/create-release.ps1) script automates steps 2 and 3:
> ```
> ./scripts/create-release.ps1 -Type Minor
> ```

Then, proceed to publish vX.Y.0 by following the [Publishing a patch release](#publishing-a-patch-release) process below.

## Publishing a patch release

This is the core release process, used for both initial minor releases (vX.Y.0) and subsequent patch releases (vX.Y.Z).

### 1. Create a release candidate

Release candidates allow us and our partners to validate a release before it is officially published.

- Create a pre-release GitHub release on the release/X.Y branch:
    - Tag: `vX.Y.Z-rc` (or `vX.Y.Z-rc2`, `vX.Y.Z-rc3` for subsequent candidates)
    - Populate the release notes automatically, update as needed
    - Check "Set as a pre-release"
- The tag triggers the internal (ADO) build, packaging and publishing pipelines automatically (VPack, NuGet, Linux packages).
    All packages are produced with a pre-release suffix, so package managers will not install them by default.
- Confirm the build and test passes are succeeding.
- If everything is as expected, approve the publication on the [Approval service](https://approval.azengsys.com/Home/PendingRelease)
    (internal link, secure station and AP_MSQUIC membership required).
- Run the [Linux package validation pipeline](/.github/workflows/validate-linux-packages.yml).
    Share the release candidate with partners for validation.
- If the release is meant to be ingested in Windows OS, ingest the release candidate first for validation.

If issues are found in the release candidate, fix them in `main` and cherry-pick the fix.
Then create a new release candidate (`vX.Y.Z-rc2`, etc.) and repeat the validation.

### 2. Publish the final release

Once a release candidate has been fully validated:

- Create a new GitHub release:
    - Pick the `release/X.Y` branch
    - Tag: `vX.Y.Z`
    - Populate the release notes automatically, update as needed
- The tag triggers the internal (ADO) build, packaging and publishing pipelines automatically (VPack, NuGet, Linux packages).
- Confirm the build and test passes are succeeding.
- If everything is as expected, approve the publication on the [Approval service](https://approval.azengsys.com/Home/PendingRelease).
- Bump the patch version on the release/X.Y branch to prepare for the next patch release:
   ```
   ./scripts/update-version.ps1 -Part Patch
   ```

**Note**: Avoid creating multiple release tags in quick succession. A known ADO issue can cause it to start the build pipeline on the wrong commit when multiple tags are mirrored at once, causing confusing failures.

### 3. Update down-level tests

If relevant test changes were present in the release (mostly relevant for minor releases), the down-level tests must be updated:

- Attach the *_test.zip artifacts from the tagged commit build run to the GitHub release.
- Update the test-down-level.yml workflow on main to point to the newly uploaded *_test.zip artifacts.

## Extra publication targets

MsQuic is published as needed to these additional targets.

### MsQuic ingestion in Windows OS

The MsQuic manifest must be updated to point to a new release VPack. VPacks are produced only for builds on a release tag.
Not every MsQuic release is ingested in the OS repository, this is done as needed.

- Once the build pipeline is completed, get the build ID from the ADO pipeline run URL.
- Update the [MsQuic manifest](https://microsoft.visualstudio.com/OS/_git/os.2020?path=/minio/netio/quic/msquic/msquic.man) (internal link) to point to the new VPack.


### Publishing MsQuic for Alpine

Prerequisites:
- Docker
- Powershell

1. Checkout to release tag. (e.g. `git checkout vX.Y.Z`)
2. Run `scripts/generate-alpine-packaging-file.ps1` from the repository root to create the `APKBUILD` file for the release.
    (This script can run on any Linux distro, and will create a docker alpine container to calculate hash keys in the APKBUILD file)
3. If you don't have account for [AlpineLinux GitLab](https://gitlab.alpinelinux.org), create one and [configure your SSH](https://docs.gitlab.com/ee/user/ssh.html).
4. If you didn't fork `aports` repository yet, fork `https://gitlab.alpinelinux.org/alpine/aports`.
5. Clone `https://gitlab.alpinelinux.org/<your_username>/aports` repository.
6. Navigate to `aports/community/libmsquic` folder.
7. Replace the `APKBUILD` file with newly created `APKBUILD` file.
8. Create a commit using `community/libmsquic: upgrade to <version_number>` (version_number e.g. 2.5.0 or 2.4.4).
9. Create a merge request using `community/libmsquic: upgrade to <version_number>` (version_number e.g. 2.5.0 or 2.4.4).
10. Owners of the `aports` repository will respond to the PR or merge it in couple of days/hours.

For future reference: [Official documentation](https://wiki.alpinelinux.org/wiki/Creating_an_Alpine_package)
