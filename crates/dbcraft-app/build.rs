//! Embeds the icon and version information in dbcraft.exe (`dbcraft.rc`, #77).

fn main() {
    println!("cargo:rerun-if-changed=dbcraft.rc");
    println!("cargo:rerun-if-changed=../../assets/icon/dbcraft.ico");
    let macros = [
        concat!("DBCRAFT_VERSION=\"", env!("CARGO_PKG_VERSION"), "\""),
        concat!("DBCRAFT_VERSION_MAJOR=", env!("CARGO_PKG_VERSION_MAJOR")),
        concat!("DBCRAFT_VERSION_MINOR=", env!("CARGO_PKG_VERSION_MINOR")),
        concat!("DBCRAFT_VERSION_PATCH=", env!("CARGO_PKG_VERSION_PATCH")),
    ];
    // Not built for Windows: nothing to do. On Windows a failing rc.exe fails
    // the build; a cross build without a resource compiler (cargo zigbuild
    // has none) only warns.
    let result = embed_resource::compile("dbcraft.rc", macros);
    if let embed_resource::CompilationResult::NotAttempted(missing) = &result {
        println!("cargo:warning=dbcraft.exe is built without its icon: no {missing}");
    }
    result.manifest_optional().unwrap();
}
