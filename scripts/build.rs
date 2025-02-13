// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cmake::Config;
use std::env;
use std::path::Path;

fn main() {
    let path_extra = "lib";
    let mut logging_enabled = "off";
    if cfg!(windows) {
        logging_enabled = "on";
    }

    let target = env::var("TARGET").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    // The output directory for the native MsQuic library.
    let quic_output_dir = Path::new(&out_dir).join("lib");

    // Builds the native MsQuic and installs it into $OUT_DIR.
    let mut config = Config::new(".");
    config
        .define("QUIC_ENABLE_LOGGING", logging_enabled)
        .define("QUIC_OUTPUT_DIR", quic_output_dir.to_str().unwrap());
    if cfg!(feature = "schannel") {
        config.define("QUIC_TLS", "schannel");
    } else {
        config.define("QUIC_TLS", "openssl");
    }
    if cfg!(feature = "static") {
        config.define("QUIC_BUILD_SHARED", "off");
    }

    // macos-latest's cargo automatically specify --target=${ARCH}-apple-macosx14.5
    // which conflicts with -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}.
    // Different value than 14.5 will cause the build to fail.
    // This hardcoded 14.5 is workaround for this issue.
    match target.as_str() {
        "x86_64-apple-darwin" => config
            .define("CMAKE_OSX_ARCHITECTURES", "x86_64")
            .define("CMAKE_OSX_DEPLOYMENT_TARGET", "14.5"),
        "aarch64-apple-darwin" => config
            .define("CMAKE_OSX_ARCHITECTURES", "arm64")
            .define("CMAKE_OSX_DEPLOYMENT_TARGET", "14.5"),
        _ => &mut config,
    };

    let dst = config.build();
    let lib_path = Path::join(Path::new(&dst), Path::new(path_extra));
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    if cfg!(feature = "static") {
        if cfg!(target_os = "linux") {
            let numa_lib_path = match target.as_str() {
                "x86_64-unknown-linux-gnu" => "/usr/lib/x86_64-linux-gnu",
                "aarch64-unknown-linux-gnu" => "/usr/lib/aarch64-linux-gnu",
                _ => panic!("Unsupported target: {}", target),
            };
            println!("cargo:rustc-link-search=native={}", numa_lib_path);
            println!("cargo:rustc-link-lib=static:+whole-archive=numa");
        } else if cfg!(target_os = "macos") {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
        }
        println!("cargo:rustc-link-lib=static=msquic");
    }

    #[cfg(all(feature = "overwrite", not(target_os = "macos")))]
    overwrite_bindgen();
}

/// Read the c header and generate rust bindings.
/// TODO: macos currently uses linux bindings.
#[cfg(all(feature = "overwrite", not(target_os = "macos")))]
fn overwrite_bindgen() {
    let manifest_dir = std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root_dir = manifest_dir;
    // include msquic headers
    let inc_dir = root_dir.join("src").join("inc");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(root_dir.join("src/ffi/wrapper.hpp").to_str().unwrap())
        .clang_arg(format!("-I{}", inc_dir.to_string_lossy()))
        .allowlist_recursively(false)
        .allowlist_item("QUIC.*|BOOLEAN|BYTE|HQUIC|HRESULT")
        .blocklist_type("QUIC_ADDR")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write bindings to the sys mod.
    let out_path = root_dir.join("src/ffi");
    #[cfg(target_os = "windows")]
    let binding_file = "win_bindings.rs";
    #[cfg(target_os = "linux")]
    let binding_file = "linux_bindings.rs";
    // TODO: support macos.
    bindings
        .write_to_file(out_path.join(binding_file))
        .expect("Couldn't write bindings!");
}
