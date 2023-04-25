
This is a mirror of [bpf-next linux tree](https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf-next)'s
`tools/lib/bpf` directory plus its supporting header files.

The following files will by sync'ed with bpf-next repo:
  - `src/` <-> `bpf-next/tools/lib/bpf/`
  - `include/uapi/linux/bpf_common.h` <-> `bpf-next/tools/include/uapi/linux/bpf_common.h`
  - `include/uapi/linux/bpf.h` <-> `bpf-next/tools/include/uapi/linux/bpf.h`
  - `include/uapi/linux/btf.h` <-> `bpf-next/tools/include/uapi/linux/btf.h`
  - `include/uapi/linux/if_link.h` <-> `bpf-next/tools/include/uapi/linux/if_link.h`
  - `include/uapi/linux/if_xdp.h` <-> `bpf-next/tools/include/uapi/linux/if_xdp.h`
  - `include/uapi/linux/netlink.h` <-> `bpf-next/tools/include/uapi/linux/netlink.h`
  - `include/tools/libc_compat.h` <-> `bpf-next/tools/include/tools/libc_compat.h`

Other header files at this repo (`include/linux/*.h`) are reduced versions of
their counterpart files at bpf-next's `tools/include/linux/*.h` to make compilation
successful.

Build
[![Build Status](https://travis-ci.org/libbpf/libbpf.svg?branch=master)](https://travis-ci.org/libbpf/libbpf)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/libbpf/libbpf.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/libbpf/libbpf/alerts/)
[![Coverity](https://img.shields.io/coverity/scan/18195.svg)](https://scan.coverity.com/projects/libbpf)
=====
libelf is an internal dependency of libbpf and thus it is required to link
against and must be installed on the system for applications to work.
pkg-config is used by default to find libelf, and the program called can be
overridden with `PKG_CONFIG`.
If using `pkg-config` at build time is not desired, it can be disabled by setting
`NO_PKG_CONFIG=1` when calling make.

To build both static libbpf.a and shared libbpf.so:
```bash
$ cd src
$ make
```

To build only static libbpf.a library in directory
build/ and install them together with libbpf headers in a staging directory
root/:
```bash
$ cd src
$ mkdir build root
$ BUILD_STATIC_ONLY=y OBJDIR=build DESTDIR=root make install
```

To build both static libbpf.a and shared libbpf.so against a custom libelf
dependency installed in /build/root/ and install them together with libbpf
headers in a build directory /build/root/:
```bash
$ cd src
$ PKG_CONFIG_PATH=/build/root/lib64/pkgconfig DESTDIR=/build/root make install
```
