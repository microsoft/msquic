// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cmake::Config;
use std::path::Path;

fn main() {
    // Builds the native MsQuic and installs it into $OUT_DIR.
    let dst = Config::new(".")
                 .define("QUIC_BUILD_TEST", "off")
                 .define("QUIC_BUILD_TOOLS", "off")
                 .define("QUIC_BUILD_PERF", "off")
                 .define("QUIC_SOURCE_LINK", "off")
                 .define("QUIC_TLS", "openssl")
                 .define("QUIC_OUTPUT_DIR", "../lib")
                 .build();
    let lib_path = Path::join(Path::new(&dst), Path::new("lib"));
    println!("cargo:rustc-link-search=native={}", lib_path.display());
}
