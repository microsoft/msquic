// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cmake::Config;
use std::path::Path;

fn main() {
    let path_extra = "lib";
    let mut logging_enabled = "off";
    if cfg!(windows) {
        logging_enabled = "on";
    }

    // Builds the native MsQuic and installs it into $OUT_DIR.
    let dst = Config::new(".")
                 .define("QUIC_ENABLE_LOGGING", logging_enabled)
                 .define("QUIC_TLS", "openssl")
                 .define("QUIC_OUTPUT_DIR", "../lib")
                 .build();
    let lib_path = Path::join(Path::new(&dst), Path::new(path_extra));
    println!("cargo:rustc-link-search=native={}", lib_path.display());
}
