#[cfg(not(windows))]
compile_error!("opencode-windows-sandbox must be built for Windows");

#[cfg(windows)]
mod windows;

#[cfg(windows)]
fn main() {
    match windows::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("opencode-windows-sandbox: {error}");
            std::process::exit(125);
        }
    }
}
