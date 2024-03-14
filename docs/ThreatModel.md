# Threat Model

## Overview

MsQuic is a library that provides a set of APIs for applications to use for networking based on the QUIC protocol. It operates in the same process as the application and uses UDP sockets and TLS for communication.

## Threat Surface

### Bottom Edge (UDP sockets and TLS)

MsQuic uses UDP sockets for transport and TLS for security. The threats at this level include:

- **Packet sniffing**: An attacker could potentially intercept the packets being sent over the network.
- **Packet tampering or injection**: An attacker could potentially modify the packets being sent over the network.
- **Denial of Service (DoS)**: An attacker could potentially flood the network with traffic, causing legitimate requests to be dropped.

Mitigations for the protocol threats include using TLS for encryption to protect against packet sniffing and tampering/injection, and protocol features to protect against DoS attacks.

Additionally, to ensure that MsQuic is secure and reliable, we leverage many different types of tests (function, stress and fuzzing) that are regularly run (every commit) in automation. We also leverage static analysis tools and ASAN on both Windows and Linux.

### Top Edge (In-proc of the calling application)

MsQuic runs in the same process as the calling application, for user mode. In the case of kernel mode clients, we also execute in kernel mode. The threats at this level include:

- **Code injection**: An attacker could potentially inject malicious code into the process.
- **Data tampering**: An attacker could potentially modify the data being sent or received by the application.

These are not actually threats to MsQuic, but rather to the application using MsQuic. We are no more priviliged than the calling application. The application should implement its own security measures to protect against these threats, including using the most up-to-date version of MsQuic to keep up with the latest security fixes.

## Conclusion

Because MsQuic is an in-proc library, it does not create any additional attack surfaces that don't already exist in the application. The primary threats are at the network level, and the QUIC protocol uses TLS to mitigate these threats. MsQuic leverages many different types of tests (function, stress and fuzzing) to ensure that it is secure and reliable.
