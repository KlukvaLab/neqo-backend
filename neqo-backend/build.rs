//! Link NSPR for the socket-level TLS API (`PR_*` functions in `nss_sys`).
//!
//! `nss-rs` already links NSS itself (`-lssl3 -lsmime3 -lnss3 -lnssutil3`
//! via pkg-config / NSS_DIR), but NSPR (`libnspr4`) is not on that link line
//! when NSS was built with `--system-nspr`. We add it explicitly.
//!
//! Override the library search directory with `NSS_LIB_DIR` if needed
//! (e.g. a custom NSPR install).

fn main() {
    if let Ok(dir) = std::env::var("NSS_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rerun-if-env-changed=NSS_LIB_DIR");
    }
    // When building against a local NSS dist, prefer its lib dir too.
    if let Ok(nss_dir) = std::env::var("NSS_DIR") {
        let candidate = std::path::Path::new(&nss_dir)
            .parent()
            .map(|p| p.join("dist").join("Release").join("lib"));
        if let Some(dir) = candidate {
            if dir.is_dir() {
                println!("cargo:rustc-link-search=native={}", dir.display());
            }
        }
        println!("cargo:rerun-if-env-changed=NSS_DIR");
    }
    println!("cargo:rustc-link-lib=dylib=nspr4");
}
