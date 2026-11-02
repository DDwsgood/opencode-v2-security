// Standalone integration payload. Built into a dedicated fixture directory by
// integration.ps1; this program is never part of the shipped helper.
use std::env;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn denied<T>(result: io::Result<T>, label: &str) {
    match result {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => println!("PASS {label}"),
        Err(error) => panic!("{label}: expected access denied, got {error}"),
        Ok(_) => panic!("{label}: operation unexpectedly succeeded"),
    }
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    let mode = arguments.get(1).expect("mode");
    let workspace = Path::new(arguments.get(2).expect("workspace"));
    match mode.as_str() {
        "check" | "readonly" => {
            let readonly = mode == "readonly";
            if readonly {
                denied(
                    fs::write(workspace.join("allowed.txt"), "changed"),
                    "readonly workspace",
                );
            } else {
                fs::write(workspace.join("allowed.txt"), "changed")
                    .expect("workspace existing write");
                fs::create_dir(workspace.join("created")).expect("workspace directory creation");
                fs::write(workspace.join("created\\nested.txt"), "new").expect("new file creation");
                assert_eq!(
                    fs::read_to_string(workspace.join("created\\nested.txt")).unwrap(),
                    "new"
                );
                let replacement = workspace.join("replacement.tmp");
                fs::write(&replacement, "atomic replacement").expect("prepare atomic save");
                fs::rename(&replacement, workspace.join("allowed.txt")).expect("atomic file replacement");
                fs::rename(workspace.join("created"), workspace.join("renamed"))
                    .expect("ordinary directory rename");
                fs::remove_file(workspace.join("renamed\\nested.txt")).expect("ordinary file delete");
                fs::remove_dir(workspace.join("renamed")).expect("ordinary directory delete");
                println!("PASS atomic replacement, rename and deletion");
                println!("PASS workspace writes");
            }
            let outside = Path::new(arguments.get(3).expect("outside"));
            denied(
                fs::write(outside.join("outside.txt"), "bad"),
                "external write",
            );
            denied(fs::read(outside.join("outside.txt")), "external read");
            let secret_read = fs::read(workspace.join("secret\\secret.txt"));
            if secret_read.is_ok() {
                let acl = Command::new("icacls.exe")
                    .arg(workspace.join("secret\\secret.txt"))
                    .output()
                    .expect("ACL failure diagnostic");
                eprintln!(
                    "denyRead ACL diagnostic: {}",
                    String::from_utf8_lossy(&acl.stdout)
                );
            }
            denied(secret_read, "denyRead descendant");
            denied(
                fs::write(workspace.join("frozen\\frozen.txt"), "bad"),
                "denyWrite descendant",
            );
            denied(
                fs::rename(workspace.join("secret"), workspace.join("moved-secret")),
                "protected subtree rename",
            );
            let temporary = env::var("TEMP").expect("private scratch");
            fs::write(Path::new(&temporary).join("scratch.txt"), "scratch").unwrap_or_else(|error| {
                panic!(
                    "scratch write in {temporary:?} (directory visible: {}): {error}",
                    Path::new(&temporary).exists()
                );
            });
            assert_eq!(
                fs::read_to_string(Path::new(&temporary).join("scratch.txt")).unwrap(),
                "scratch"
            );
            assert!(env::var_os("INTEGRATION_SECRET_CANARY").is_none());
            assert!(env::var_os("TOTALLY_CUSTOM_CANARY").is_none());
            assert!(!env::vars_os().any(|(key, _)| {
                key.to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with("OPENCODE_")
            }));
            println!("PASS scratch and secret environment");
            for address in arguments.iter().skip(4) {
                let address: SocketAddr = address.parse().unwrap();
                denied(
                    TcpStream::connect_timeout(&address, Duration::from_secs(3)),
                    &format!("network {address}"),
                );
            }
        }
        "concurrent-write" => {
            let name = arguments.get(3).expect("concurrent fixture name");
            let delay = arguments.get(4).expect("concurrent delay").parse::<u64>().unwrap();
            println!("READY");
            thread::sleep(Duration::from_millis(delay));
            fs::write(workspace.join(name), "concurrent").expect("concurrent scoped write");
        }
        "descendant" => {
            let executable = env::current_exe().unwrap();
            let child = Command::new(executable)
                .args(["late-write", workspace.to_str().unwrap()])
                .spawn()
                .unwrap();
            println!("CHILD {}", child.id());
        }
        "wait-descendant" => {
            let executable = env::current_exe().unwrap();
            let child = Command::new(executable)
                .args(["late-write", workspace.to_str().unwrap()])
                .spawn()
                .unwrap();
            println!("CHILD {}", child.id());
            thread::sleep(Duration::from_secs(30));
        }
        "late-write" => {
            thread::sleep(Duration::from_secs(2));
            fs::write(workspace.join("escaped-child.txt"), "bad").unwrap();
        }
        _ => panic!("unknown payload mode"),
    }
}
