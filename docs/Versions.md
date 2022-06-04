# QUIC Versions and Version Negotiation

The QUIC protocol features a Version field to enable the protocol to evolve and have future versions, multiple of which may be supported by a given implementation.
MsQuic is no exception and currently supports Draft-29 and Version 1 of the QUIC protocol.
By default, MsQuic clients start all connections with Version 1.  MsQuic servers support Version 1 and Draft-29.

The [Version Negotiation Extension](https://tools.ietf.org/html/draft-ietf-quic-version-negotiation) is supported in MsQuic and is keeping pace with changes in the standard.  It is enabled by default on both MsQuic client and server.

## Configuring QUIC Versions on MsQuic Clients

An application may decide that it needs a specific feature only availble in one version of QUIC. The application may also wish to change the order of preference of supported version in MsQuic. Both scenarios are supported via the `QUIC_VERSION_SETTINGS` struct.  Since there are three different version lists, the client **MUST** set all three to be the same.

The first version in the list of `FullyDeployedVersions` will always be the initial version MsQuic starts the connection with.

> **Warning**
> A client may only set a version that MsQuic supports. Any other value will cause [`SetParam`](api/SetParam.md) to fail.

Use the following code snippet to change the default initial version, and only support a single QUIC version. It must be used before [`ConnectionStart`](api/ConnectionStart.md) is called:
```c
QUIC_VERSION_SETTINGS Settings = { 0 };
const uint32_t SupportedVersion = 0xff00001dU; // This is the Draft-29 version in HOST byte order. If the server does not support this, the connection will fail.
Settings.AcceptableVersionsList = &SupportedVersion;
Settings.AcceptableVersionsListLength = 1;
Settings.OfferedVersionsList = &SupportedVersion;
Settings.OfferedVersionsListLength = 1;
Settings.FullyDeployedVersionsList = &SupportedVersion;
Settings.FullyDeployedVersionsListLength = 1;

MsQuic->SetParam(
    Connection,
    QUIC_PARAM_CONN_VERSION_SETTINGS,
    sizeof(Settings),
    &Settings);
```

Changing the order of supported versions is the same as above, with the following change:
```c
QUIC_VERSION_SETTINGS Settings = { 0 };
const uint32_t SupportedVersions[2] = {
    0xff00001dU, // This is the Draft-29 version in HOST byte order. It will be used first.
    0x00000001U // QUIC version 1 in HOST byte order. It will be used if a VN packet is received.
};
Settings.AcceptableVersionsList = SupportedVersions;
Settings.AcceptableVersionsListLength = 2;
Settings.OfferedVersionsList = SupportedVersions;
Settings.OfferedVersionsListLength = 2;
Settings.FullyDeployedVersionsList = SupportedVersions;
Settings.FullyDeployedVersionsListLength = 2;
```

The `QUIC_VERSION_SETTINGS` can be set on a single `QUIC_CONNECTION`, as well as a `QUIC_CONFIGURATION` with [`SetParam`](api/SetParam.md).

## Configuring QUIC Versions on MsQuic Servers

A server application may also want to restrict the QUIC versions it supports to ensure a specific feature is available, or to prevent older versions of QUIC from being used.
Configuring the QUIC versions on a MsQuic server is similar to configuring them on a client, however, the setting for server **MUST** be set globally, and not on the `QUIC_CONFIGURATION` used for the `QUIC_LISTENER` or `QUIC_CONNECTION`.

If a server is not in a fleet, or the operator/application does not ever need to change QUIC versions, then all three lists in `QUIC_VERSION_SETTINGS` **MUST** be the same.

If a server is deployed in a fleet, and the server operator wishes to change the supported QUIC versions, the Version Negotiation specification details how that should be done, quoted here:
> When adding support for a new version:
> * The first step is to progressively add support for the new version to all server instances. This step updates the Acceptable Versions but not the Offered Versions nor the Fully-Deployed Versions. Once all server instances have been updated, operators wait for at least one MSL to allow any in-flight Version Negotiation packets to arrive.
> * Then, the second step is to progressively add the new version to Offered Versions on all server instances. Once complete, operators wait for at least another MSL.
> * Finally, the third step is to progressively add the new version to Fully-Deployed Versions on all server instances.
>
> When removing support for a version:
> * The first step is to progressively remove the version from Fully-Deployed Versions on all server instances. Once it has been removed on all server instances, operators wait for at least one MSL to allow any in-flight Version Negotiation packets to arrive.
> * Then, the second step is to progressively remove the version from Offered Versions on all server instances. Once complete, operators wait for at least another MSL.
> * Finally, the third step is to progressively remove support for the version from all server instances. That step updates the Acceptable Versions.

**Note that this opens connections to version downgrades (but only for partially-deployed versions) during the update window, since those could be due to clients communicating with both updated and non-updated server instances.**


This snippet should execute before the server's `QUIC_CONFIGURATION` is created:
```c
QUIC_VERSION_SETTINGS Settings = { 0 };
const uint32_t SupportedVersions[2] = {
    0xff00001dU, // This is the Draft-29 version in HOST byte order. It will be preferred over Version 1.
    0x00000001U // QUIC version 1 in HOST byte order. It will be used if a client starts with Version 1, instead of Draft-29.
};
Settings.AcceptableVersionsList = SupportedVersion;
Settings.AcceptableVersionsListLength = 2;
Settings.OfferedVersionsList = SupportedVersion;
Settings.OfferedVersionsListLength = 2;
Settings.FullyDeployedVersionsList = SupportedVersion;
Settings.FullyDeployedVersionsListLength = 2;

MsQuic->SetParam(
    NULL,
    QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
    sizeof(Settings),
    &Settings);
```

# QUIC Version Negotiation Extension

The Version Negotiation Extension is on by default in our officially-released binaries. Since the standard is not yet complete, incompatible changes may be made preventing different drafts from working with each other. An application using MsQuic should be cautious about enabling the Version Negotiation Extension in production scenarios until the standard is complete.

## Enabling Version Negotiation Extension on MsQuic Client

The Version Negotiation Extension is enabled on client when `QUIC_VERSION_SETTINGS` are set on the `QUIC_CONFIGURATION` or `QUIC_CONNECTION` via [`SetParam`](api/SetParam.md).
This setting **MUST** be set before [`ConnectionStart`](api/ConnectionStart.md) to take effect.

## Enabling Version Negotiation Extension on MsQuic Server

Enabling the Version Negotiation Extension on server follows the same restrictions as setting the QUIC version on server, i.e. it **MUST** be set globally, using [`SetParam`](api/SetParam.md) before the `QUIC_CONFIGURATION` is opened for the server. It is set automatically when `QUIC_VERSION_SETTINGS` are set.
