// ------------------------------------------------------------
// Copyright 2024 Youyuan Wu
// Licensed under the MIT License (MIT). See License in the repo root for
// license information.
// ------------------------------------------------------------

use windows_bindgen::{bindgen, Result};

fn main() -> Result<()> {
    let log = bindgen([
        "--in",
        "./crates/.windows/winmd/Microsoft.MsQuic.winmd",
        "--out",
        "crates/libs/msquic-rs/src/Microsoft.rs",
        "--filter",
        "Microsoft",
        "!Microsoft.MsQuic.MsQuicOpenVersion", // Skip functions that needs linking
        "!Microsoft.MsQuic.MsQuicClose",
        "--config",
        "implement",
    ])?;
    println!("{}", log);
    Ok(())
}
