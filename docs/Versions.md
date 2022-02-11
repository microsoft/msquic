# QUIC Versions and Version Negotiation

The QUIC protocol features a Version field to enable the protocol to evolve and have future versions, multiple of which may be supported by a given implementation.
MsQuic is no exception and currently supports Draft-29 and Version 1 of the QUIC protocol.
By default, MsQuic clients start all connections with Version 1.  MsQuic servers support Version 1 and Draft-29.

The [Version Negotiation Extension](https://tools.ietf.org/html/draft-ietf-quic-version-negotiation) is supported in MsQuic and is keeping pace with changes in the standard.  It is disabled by default on both MsQuic client and server.

## Configuring QUIC Versions on MsQuic Clients

An application may decide that it needs a specific feature only availble in one version of QUIC. The application may also wish to change the order of preference of supported version in MsQuic. Both scenarios are supported via the `QUIC_SETTINGS` struct.

The first version in the list of `DesiredVersions` will always be the initial version MsQuic starts the connection with.

**NOTE: A client may only set a version that MsQuic supports. Any other value will cause [`SetParam`](api/SetParam.md) to fail.**

Use the following code snippet to change the default initial version, and only support a single QUIC version. It must be used before [`ConnectionStart`](api/ConnectionStart.md) is called:
```c
QUIC_SETTINGS Settings = { 0 };
const uint32_t DesiredVersion = 0xff00001dU; // This is the Draft-29 version in HOST byte order. If the server does not support this, the connection will fail.
Settings.DesiredVersionsList = &DesiredVersion;
Settings.DesiredVersionsListLength = 1;
Settings.IsSet.DesiredVersionsList = TRUE;

MsQuic->SetParam(
    Connection,
    QUIC_PARAM_CONN_SETTINGS,
    sizeof(Settings),
    &Settings);
```

Changing the order of supported versions is the same as above, with the following change:
```c
QUIC_SETTINGS Settings = { 0 };
const uint32_t DesiredVersions[2] = {
    0xff00001dU, // This is the Draft-29 version in HOST byte order. It will be used first.
    0x00000001U // QUIC version 1 in HOST byte order. It will be used if a VN packet is received.
};
Settings.DesiredVersionsList = DesiredVersions;
Settings.DesiredVersionsListLength = 2;
Settings.IsSet.DesiredVersionsList = TRUE;
```

The `QUIC_SETTINGS` which sets the desired QUIC version can be used in the [`ConfigurationOpen`](api/ConfigurationOpen.md) call and doesn't need to used exclusively with [`SetParam`](api/SetParam.md).

## Configuring QUIC Versions on MsQuic Servers

A server application may also want to restrict the QUIC versions it supports to ensure a specific feature is available, or to prevent older versions of QUIC from being used.
Configuring the QUIC versions on a MsQuic server is similar to configuring them on a client, however, the setting for server **MUST** be set globally, and not on the `QUIC_CONFIGURATION`.

This snippet should execute before the server's `QUIC_CONFIGURATION` is created:
```c
QUIC_SETTINGS Settings = { 0 };
const uint32_t DesiredVersions[2] = {
    0xff00001dU, // This is the Draft-29 version in HOST byte order. It will be preferred over Version 1.
    0x00000001U // QUIC version 1 in HOST byte order. It will be used if a client starts with Version 1, instead of Draft-29.
};
Settings.DesiredVersionsList = DesiredVersions;
Settings.DesiredVersionsListLength = 2;
Settings.IsSet.DesiredVersionsList = TRUE;

MsQuic->SetParam(
    NULL,
    QUIC_PARAM_CONN_SETTINGS,
    sizeof(Settings),
    &Settings);
```

# QUIC Version Negotiation Extension

The Version Negotiation Extension is off by default. Since the standard is not yet complete, incompatible changes may be made preventing different drafts from working with each other. An application using MsQuic should be cautious about enabling the Version Negotiation Extension in production scenarios until the standard is complete.

## Enabling Version Negotiation Extension on MsQuic Client

The Version Negotiation Extension is enabled on client the same as the QUIC version. It can also be set via [`ConfigurationOpen`](api/ConfigurationOpen.md), as well as via [`SetParam`](api/SetParam.md).
This setting **MUST** be set before [`ConnectionStart`](api/ConnectionStart.md) to take effect.

```c
QUIC_SETTINGS Settings = { 0 };
Settings.VersionNegotiationExtEnabled = TRUE;
Settings.IsSet.VersionNegotiationExtEnabled = TRUE;

MsQuic->SetParam(
    Connection,
    QUIC_PARAM_CONN_SETTINGS,
    sizeof(Settings),
    &Settings);
```

## Enabling Version Negotiation Extension on MsQuic Server

Enabling the Version Negotiation Extension on server follows the same restrictions as setting the QUIC version on server, i.e. it **MUST** be set globally, using [`SetParam`](api/SetParam.md) before the `QUIC_CONFIGURATION` is opened for the server.

```c
QUIC_SETTINGS Settings = { 0 };
Settings.VersionNegotiationExtEnabled = TRUE;
Settings.IsSet.VersionNegotiationExtEnabled = TRUE;

MsQuic->SetParam(
    NULL,
    QUIC_PARAM_CONN_SETTINGS,
    sizeof(Settings),
    &Settings);
```