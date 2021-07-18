// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

fn get_output_path() -> PathBuf {
    //<root or manifest path>/target/<profile>/
    let manifest_dir_string = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_type = env::var("PROFILE").unwrap();
    let path = Path::new(&manifest_dir_string).join("target").join(build_type);
    return PathBuf::from(path);
}

fn main() {

    // TODO - Currently this build requires that msquic was separately prebuilt
    // via its normal cmake build. This build script should be updated to call
    // cmake directly.

    let config = env::var("PROFILE").unwrap(); // debug or release

    let mut arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if arch == "x86_64" {
        arch = "x64".to_string(); // MsQuic uses 'x64' instead of 'x86_x64'
    }

    // Platform specific bits
    let mut os = "linux";
    let mut bin = "libmsquic.so";
    if cfg!(target_os = "windows") {
        os = "windows";
        bin = "msquic.dll";
    }

    let mut tls = "openssl";
    if cfg!(feature = "use-schannel") { // TODO - Figure out how to make this work.
        tls = "schannel";
    }

    // Build up the search directory for the build artifacts.
    let build_dir = format!("artifacts/bin/{}/{}_{}_{}", os, arch, config, tls);

    // Set Cargo's search path to find the native MsQuic library.
    println!("cargo:rustc-link-search=native={}", build_dir);

    // Copy the native MsQuic binary to the output path.
    let target_dir = get_output_path();
    let from_path = format!("{}/{}", build_dir, bin);
    let to_path = Path::join(Path::new(&target_dir), Path::new(bin));
    fs::copy(from_path, to_path).unwrap();
}
