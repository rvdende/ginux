//! Embeds build/rootfs-rust.tar.gz, made by tools/images/build-rust-rootfs.sh,
//! as the root filesystem of `image=builtin://rust` domains. Without that
//! file the image is empty and builtin://rust is unavailable, so the loader
//! still builds from a plain checkout.

use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let rootfs = manifest_dir.join("../../build/rootfs-rust.tar.gz");
    println!("cargo:rerun-if-changed={}", rootfs.display());
    let source = match rootfs.canonicalize() {
        Ok(path) if path.is_file() => {
            format!("pub(crate) static BUILTIN_ROOTFS: &[u8] = include_bytes!({path:?});\n")
        }
        _ => "pub(crate) static BUILTIN_ROOTFS: &[u8] = &[];\n".to_string(),
    };
    let output = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("builtin_rootfs.rs");
    fs::write(output, source).expect("write builtin_rootfs.rs");
}
