
fn main() {
    {
        let path = env!("CARGO_MANIFEST_DIR");
        if cfg!(target_vendor = "apple") {
            println!("cargo:rustc-flags=-L {}/saprfc/osx/nwrfcsdk/lib", path);
        } else {
            println!("cargo:rustc-flags=-L {}/saprfc/gnulinux/nwrfcsdk/lib", path);
        }
    }
}
