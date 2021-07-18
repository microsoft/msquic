// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    let mut tls = "openssl";
    let arch = "x64"; // TODO - how to get this from config
    let config = "debug"; // TODO - how to get this from config
    let mut os = "linux";

    if cfg!(target_os = "windows") {
        os = "windows";
    }
    if cfg!(feature = "use-schannel") {
        tls = "schannel";
    }

    // Build up the search directory for the build artifacts.
    let build_dir = format!("artifacts/bin/{}/{}_{}_{}", os, arch, config, tls);
    println!("cargo:rustc-link-search=native={}", build_dir);
}