use std::env;

fn main() {
    let manifest_dir = std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root_dir = manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let inc_dir = root_dir.join("src").join("inc");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(
            root_dir
                .join("crates/tools/api/wrapper.hpp")
                .to_str()
                .unwrap(),
        )
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
    let out_path = root_dir.join("crates/libs/msquic-rs2").join("src/sys");
    #[cfg(target_os = "windows")]
    let binding_file = "win_bindings.rs";
    #[cfg(target_os = "linux")]
    let binding_file = "linux_bindings.rs";
    bindings
        .write_to_file(out_path.join(binding_file))
        .expect("Couldn't write bindings!");
}
