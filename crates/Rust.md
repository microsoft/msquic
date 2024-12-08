# msquic Rust

Rust binding for msquic is auto generated from c headers using win32metadata and windows-bindgen toolchain.
Generated bindings is cross platform with use use of [mssf-pal](https://github.com/Azure/service-fabric-rs/tree/main/crates/libs/pal).
The c functions that require linking are not included in the generated code for now, and the crate can be built without installing msquic shared libraries. Most likely these functions will be dynamically loaded in future.(This is subjected to change.)

## Regenerate code
```ps1
# generate winmd
dotnet build .\crates\.metadata\
# generate rust code
cargo run -p tools_api
# build generated code
cargo build -p msquic-rs
```