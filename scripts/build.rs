// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cmake::Config;
use std::path::Path;
use std::env;

fn main() {
    let mut logging_enabled = "off";
    if cfg!(windows) {
        logging_enabled = "on";
    }

    let target = env::var("TARGET").unwrap();
    let out_path = std::env::var("OUT_DIR").unwrap();
    let deps_path = Path::new(&out_path).join("deps/");

    // Builds the native MsQuic and installs it into $OUT_DIR.
    let mut config = Config::new(".");
    config
        .define("QUIC_ENABLE_LOGGING", logging_enabled)
        .define("QUIC_TLS", "openssl")
        .define("QUIC_OUTPUT_DIR", deps_path.to_str().unwrap())
        .define("CARGO_BUILD", "on");

    match target.as_str() {
        "x86_64-apple-darwin" => config
            .define("CMAKE_OSX_ARCHITECTURES", "x86_64")
            .define("CMAKE_OSX_DEPLOYMENT_TARGET", "10.15"),
        "aarch64-apple-darwin" => config
            .define("CMAKE_OSX_ARCHITECTURES", "arm64")
            .define("CMAKE_OSX_DEPLOYMENT_TARGET", "11.0"),
        _ => &mut config
    };

    let _ = config.build();
    println!("cargo:rustc-link-search=native={}", deps_path.display());
}