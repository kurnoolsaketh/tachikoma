use crate::Result;
use crate::ssh::SshClient;
use crate::state::StateStore;
use crate::tart::TartRunner;

pub async fn run(
    vm_name: &str,
    cmd: &[String],
    tart: &dyn TartRunner,
    ssh: &dyn SshClient,
    state_store: &dyn StateStore,
    ssh_user: &str,
    use_tart_exec: bool,
) -> Result<String> {
    let full_cmd = cmd.join(" ");

    if use_tart_exec {
        let output = tart
            .exec(
                vm_name,
                vec!["bash".to_string(), "-c".to_string(), full_cmd],
            )
            .await?;

        if output.exit_code != 0 {
            return Err(crate::TachikomaError::Tart(format!(
                "tart exec failed (exit {}): {}",
                output.exit_code,
                output.stderr.trim()
            )));
        }

        return Ok(output.stdout);
    }

    // SSH path (default)
    let state = state_store.load().await?;
    let entry = state
        .find_vm(vm_name)
        .ok_or_else(|| crate::TachikomaError::Vm(format!("VM '{vm_name}' not found")))?;

    let ip = entry.parsed_ip()?;
    ssh.run_command(ip, ssh_user, &full_cmd).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::MockSshClient;
    use crate::state::{MockStateStore, State, VmEntry, VmStatus};
    use crate::tart::MockTartRunner;
    use crate::tart::types::ExecOutput;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_exec_via_tart_exec() {
        let mut tart = MockTartRunner::new();
        tart.expect_exec()
            .withf(|name, cmd| name == "test-vm" && cmd == &["bash", "-c", "echo hello"])
            .returning(|_, _| {
                Ok(ExecOutput {
                    stdout: "hello\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                })
            });

        let ssh = MockSshClient::new();
        let state_store = MockStateStore::new();

        let result = run(
            "test-vm",
            &["echo".into(), "hello".into()],
            &tart,
            &ssh,
            &state_store,
            "admin",
            true,
        )
        .await
        .unwrap();

        assert_eq!(result, "hello\n");
    }

    #[tokio::test]
    async fn test_exec_via_tart_exec_failure() {
        let mut tart = MockTartRunner::new();
        tart.expect_exec().returning(|_, _| {
            Ok(ExecOutput {
                stdout: String::new(),
                stderr: "command not found\n".to_string(),
                exit_code: 127,
            })
        });

        let ssh = MockSshClient::new();
        let state_store = MockStateStore::new();

        let result = run(
            "test-vm",
            &["badcmd".into()],
            &tart,
            &ssh,
            &state_store,
            "admin",
            true,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exit 127"), "got: {err}");
        assert!(err.contains("command not found"), "got: {err}");
    }

    #[tokio::test]
    async fn test_exec_via_ssh() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 64, 10));
        let tart = MockTartRunner::new();

        let mut ssh = MockSshClient::new();
        ssh.expect_run_command()
            .returning(|_, _, _| Ok("hello\n".to_string()));

        let mut state_store = MockStateStore::new();
        state_store.expect_load().returning(move || {
            let mut state = State::new();
            state.add_vm(VmEntry {
                name: "test-vm".to_string(),
                repo: "repo".to_string(),
                branch: "main".to_string(),
                worktree_path: PathBuf::from("/tmp/wt"),
                created_at: chrono::Utc::now(),
                last_used: chrono::Utc::now(),
                status: VmStatus::Running,
                ip: Some(ip.to_string()),
            });
            Ok(state)
        });

        let result = run(
            "test-vm",
            &["echo".into(), "hello".into()],
            &tart,
            &ssh,
            &state_store,
            "admin",
            false,
        )
        .await
        .unwrap();

        assert_eq!(result, "hello\n");
    }
}
