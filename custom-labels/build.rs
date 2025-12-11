fn main() {
    println!("cargo:rerun-if-changed=src/customlabels.c");
    println!("cargo:rerun-if-changed=src/customlabels.h");
    println!("cargo:rerun-if-changed=src/customlabels_v2.h");
    println!("cargo:rerun-if-changed=src/customlabels_v2.c");
    println!("cargo:rerun-if-changed=./dlist");

    cc::Build::new()
        .file("src/customlabels.c")
        .file("src/customlabels_v2.c")
        .compile("customlabels");

    println!("cargo:rustc-link-lib=static=customlabels");

    // dynamic-list is Linux-only
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-link-arg=-Wl,--dynamic-list=./dlist");

    // Generate bindings using bindgen
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // V1 bindings
    let bindings_v1 = bindgen::Builder::default()
        .header("src/customlabels.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate v1 bindings");
    bindings_v1
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write v1 bindings!");

    // V2 bindings
    let bindings_v2 = bindgen::Builder::default()
        .header("src/customlabels_v2.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate v2 bindings");
    bindings_v2
        .write_to_file(out_path.join("bindings_v2.rs"))
        .expect("Couldn't write v2 bindings!");
}
