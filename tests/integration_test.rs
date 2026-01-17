use std::fs;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_full_pipeline_udp() {
    let output_file = "test_output_udp.lshrink";
    let binary_path = "target/debug/sankshepa";

    if fs::metadata(output_file).is_ok() {
        let _ = fs::remove_file(output_file);
    }

    // 1. Start sankshepa serve
    let mut serve_child = Command::new(binary_path)
        .args(&[
            "serve",
            "--udp-addr",
            "127.0.0.1:12514",
            "--tcp-addr",
            "127.0.0.1:12515",
            "--beep-addr",
            "127.0.0.1:12601",
            "--output",
            output_file,
        ])
        .spawn()
        .expect("Failed to start serve");

    sleep(Duration::from_secs(2)).await;

    // 2. Run sankshepa generate
    let gen_status = Command::new(binary_path)
        .args(&[
            "generate",
            "--addr",
            "127.0.0.1:12514",
            "--count",
            "50",
            "--protocol",
            "udp",
        ])
        .status()
        .expect("Failed to run generate");

    assert!(gen_status.success());
    sleep(Duration::from_secs(1)).await;

    // 3. Stop serve with SIGINT
    #[cfg(unix)]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;
        signal::kill(Pid::from_raw(serve_child.id() as i32), Signal::SIGINT).unwrap();
    }

    let _ = serve_child.wait();

    // 4. Verify output file exists
    assert!(
        fs::metadata(output_file).is_ok(),
        "Output file {} should exist",
        output_file
    );

    // 5. Run query
    let query_output = Command::new(binary_path)
        .args(&["query", "--input", output_file])
        .output()
        .expect("Failed to run query");

    let stdout = String::from_utf8_lossy(&query_output.stdout);
    let count = stdout.lines().count();
    println!("Total logs found in last chunk: {}", count);
    assert!(count >= 10, "Expected at least 10 logs, found {}", count);

    // Cleanup
    let _ = fs::remove_file(output_file);
}

#[tokio::test]
async fn test_full_pipeline_tcp() {
    let output_file = "test_output_tcp.lshrink";
    let binary_path = "target/debug/sankshepa";

    if fs::metadata(output_file).is_ok() {
        let _ = fs::remove_file(output_file);
    }

    // 1. Start sankshepa serve
    let mut serve_child = Command::new(binary_path)
        .args(&[
            "serve",
            "--udp-addr",
            "127.0.0.1:13514",
            "--tcp-addr",
            "127.0.0.1:13515",
            "--beep-addr",
            "127.0.0.1:13601",
            "--output",
            output_file,
        ])
        .spawn()
        .expect("Failed to start serve");

    sleep(Duration::from_secs(2)).await;

    // 2. Run sankshepa generate
    let gen_status = Command::new(binary_path)
        .args(&[
            "generate",
            "--addr",
            "127.0.0.1:13515",
            "--count",
            "50",
            "--protocol",
            "tcp",
        ])
        .status()
        .expect("Failed to run generate");

    assert!(gen_status.success());
    sleep(Duration::from_secs(1)).await;

    // 3. Stop serve with SIGINT
    #[cfg(unix)]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;
        signal::kill(Pid::from_raw(serve_child.id() as i32), Signal::SIGINT).unwrap();
    }

    let _ = serve_child.wait();

    // 4. Verify output file exists
    assert!(fs::metadata(output_file).is_ok());

    // 5. Run query
    let query_output = Command::new(binary_path)
        .args(&["query", "--input", output_file])
        .output()
        .expect("Failed to run query");

    let stdout = String::from_utf8_lossy(&query_output.stdout);
    let count = stdout.lines().count();
    println!("Total logs found in last TCP chunk: {}", count);
    assert!(count >= 10);

    // Cleanup
    let _ = fs::remove_file(output_file);
}
