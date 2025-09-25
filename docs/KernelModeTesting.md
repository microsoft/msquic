# Collecting Kernel Memory Dumps

MsQuic generally leverages the runner agents provided by Github, and some custom Azure 1ES pools for running all of it's functional / performance / stess tests.
However, MsQuic can also be run in Kernel mode to exercises the Kernel datapaths (wsk sockets). This means bugchecks can happen, but we have no way of collecting
the crash dump using the existing Github runners / Azure 1ES agents.

# Self hosted runners

Luckily, we have an on-prem lab in Netperf that can be used to run these tests and collect crash dumps when needed. Maintainers of MsQuic with write-access will be able to
kick off a pipeline to trigger a Kernel BVT run on this self-hosted lab.

Action workflow name: `Kernel BVT Crashdumps` (manual workflow dispatch only)

Note that the Windows image version used for the self-hosted runner mirrors a version used previously in our WinPrerelease Azure 1ES pool.
Specific version information: 29439.1000.rs_prerelease.250829-1439

Details on the machine can be found in Netperf.
