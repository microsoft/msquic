// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    #[cfg(all(feature = "src", feature = "find"))]
    panic!("feature src and find are mutually exclusive");

    #[cfg(feature = "src")]
    cmake_build();

    #[cfg(feature = "find")]
    find::find();

    #[cfg(all(feature = "overwrite", not(target_os = "macos")))]
    overwrite_bindgen();
}

#[cfg(feature = "src")]
fn cmake_build() {
    use cmake::Config;
    use std::env;
    use std::path::Path;
    let path_extra = "lib";
    let mut logging_enabled = "off";
    if cfg!(windows) {
        logging_enabled = "on";
    }

    let target = env::var("TARGET").unwrap().replace("\\", "/");
    let out_dir = env::var("OUT_DIR").unwrap().replace("\\", "/");
    // The output directory for the native MsQuic library.
    let libdir = "/lib";
    let full_out_dir = [out_dir, libdir.to_string()].join("");
    let quic_output_dir = Path::new(&full_out_dir);

    // Builds the native MsQuic and installs it into $OUT_DIR.
    let mut config = Config::new(".");
    config
        .define("QUIC_ENABLE_LOGGING", logging_enabled)
        .define("QUIC_OUTPUT_DIR", quic_output_dir.to_str().unwrap());

    // Disable parallel builds on Windows, as they seems to break manifest builds.
    if cfg!(windows) {
        // cmake-rs uses this cargo env var to pass "--parallel" arg to cmake
        std::env::remove_var("NUM_JOBS");
    }

    // By default enable schannel on windows, unless openssl feature is selected.
    if cfg!(feature = "quictls") {
        config.define("QUIC_TLS_LIB", "quictls");
    } else if cfg!(feature = "openssl") {
        config.define("QUIC_TLS_LIB", "openssl");
    } else if cfg!(windows) {
        config.define("QUIC_TLS_LIB", "schannel");
    } else {
        // Default to quictls
        config.define("QUIC_TLS_LIB", "quictls");
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
                _ => panic!("Unsupported target: {target}"),
            };
            println!("cargo:rustc-link-search=native={numa_lib_path}");
            println!("cargo:rustc-link-lib=static:+whole-archive=numa");
        } else if cfg!(target_os = "macos") {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
        }
    }
}

#[cfg(feature = "find")]
mod find {
    use std::path::{Path, PathBuf};

    /// Find and use preinstalled msquic binaries.
    pub(crate) fn find() {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let libs = if cfg!(target_os = "linux") {
            // On linux try the known install location of libmsquic pkg.
            try_system_location().expect("cannot find msquic in system")
        } else {
            // On windows try find from vcpkg.
            try_vcpkg().expect("cannot find msquic in vcpkg")
        };
        #[cfg(target_os = "windows")]
        copy_libs(&libs, &out_dir);

        #[cfg(not(target_os = "windows"))]
        symlink_libs(&libs, &out_dir);
        println!("cargo:rustc-link-search=native={}", out_dir.display());
    }

    #[cfg(target_os = "windows")]
    const LIBS: [&str; 3] = ["bin/msquic.dll", "bin/msquic.pdb", "lib/msquic.lib"];

    #[cfg(not(target_os = "windows"))]
    const LIBS: [&str; 1] = ["libmsquic.so.2"];

    /// Get libs for preinstalled msquic.
    fn get_preinstalled_libs(install_dir: &Path) -> Vec<PathBuf> {
        LIBS.iter().map(|lib| install_dir.join(lib)).collect()
    }

    /// Copy libs from pre-installed dir to rust out_dir.
    /// This ensures cargo link msquic from this dir, and propagates right
    /// variables for test executables to load msquic.
    #[cfg(target_os = "windows")]
    fn copy_libs(libs: &[PathBuf], out_dir: &Path) {
        for lib in libs {
            let lib_out = out_dir.join(lib.file_name().unwrap());
            if !lib_out.exists() {
                assert!(lib.exists()); // we have checked it in prior steps.
                std::fs::copy(lib, &lib_out).expect("cannot copy file");
            }
        }
    }

    /// On unix we can just symlink the libmsquic.so.2 file to outdir as libmsquic.so
    #[cfg(not(target_os = "windows"))]
    fn symlink_libs(libs: &[PathBuf], out_dir: &Path) {
        let lib = libs.first().unwrap(); // There is only 1 so file on unix
        let lib_out = out_dir.join("libmsquic.so");
        if !lib_out.exists() {
            std::os::unix::fs::symlink(lib, out_dir.join("libmsquic.so"))
                .expect("cannot symlink file");
        }
    }

    /// Try get msquic libs from vcpkg. Return the list of lib full paths.
    /// vcpkg crate is not maintained, and does not work well on linux,
    /// so we write this simple logic from scratch.
    fn try_vcpkg() -> Option<Vec<PathBuf>> {
        let vcpkg_dir = std::env::var("VCPKG_ROOT").ok()?;
        let triplet = if cfg!(target_os = "windows") {
            "x64-windows"
        } else if cfg!(target_os = "linux") {
            "x64-linux"
        } else {
            panic!("os not supported");
        };
        let dir = PathBuf::from(vcpkg_dir).join("installed").join(triplet);
        if !dir.exists() {
            return None;
        }
        let libs = get_preinstalled_libs(&dir);
        for lib in &libs {
            if !lib.exists() {
                return None;
            }
        }
        Some(libs)
    }

    /// Try get from system installed location. Linux only.
    fn try_system_location() -> Option<Vec<PathBuf>> {
        let installed_dir = "/usr/lib/x86_64-linux-gnu";
        let libs = get_preinstalled_libs(&PathBuf::from(installed_dir));
        for lib in &libs {
            if !lib.exists() {
                return None;
            }
        }
        Some(libs)
    }
}

/// Read the c header and generate rust bindings.
/// TODO: macos currently uses linux bindings.
#[cfg(all(feature = "overwrite", not(target_os = "macos")))]
fn overwrite_bindgen() {
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root_dir = manifest_dir;
    // include msquic headers
    let inc_dir = root_dir.join("src").join("inc");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(root_dir.join("src/rs/ffi/wrapper.hpp").to_str().unwrap())
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
    let out_path = root_dir.join("src/rs/ffi");
    #[cfg(target_os = "windows")]
    let binding_file = "win_bindings.rs";
    #[cfg(target_os = "linux")]
    let binding_file = "linux_bindings.rs";
    // TODO: support macos.
    bindings
        .write_to_file(out_path.join(binding_file))
        .expect("Couldn't write bindings!");
}
