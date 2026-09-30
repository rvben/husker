//! Development-computer workflow over the existing context and VM contracts.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use husker_api::{ExecRequest, SessionEventsResponse, SessionInfo, SessionState};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

use crate::cli::{DevAction, OutputFormat, SessionAction};
use crate::daemon_client::DaemonClient;
use crate::daemon_target::DaemonTarget;
use crate::vm_creation::{VmCreationIntent, VmRequestArgs, plan_vm_creation};

const PROVISION: &str = include_str!("../../../guest/dev/provision.sh");
const CHECK: &str = "set -eu; git --version; node --version; python3 --version; RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo rustc --version; codex --version; runuser -u developer -- claude --version; docker info >/dev/null; test -d /workspace; cat /etc/husker/dev-manifest.txt";
const START_DOCKER: &str = "set -eu; mkdir -p /var/log/husker; if ! docker info >/dev/null 2>&1; then nohup dockerd </dev/null >/var/log/husker/docker.log 2>&1 & fi; n=0; until docker info >/dev/null 2>&1; do n=$((n+1)); if [ \"$n\" -ge 60 ]; then cat /var/log/husker/docker.log >&2; exit 1; fi; sleep 1; done";

fn segment(name: &str) -> Result<&str> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid resource name"
    );
    Ok(name)
}

fn exec_request(
    command: Vec<String>,
    workdir: Option<String>,
    timeout: u64,
) -> Result<ExecRequest> {
    let (command, args) = command.split_first().context("command required after --")?;
    Ok(ExecRequest {
        command: command.clone(),
        args: args.to_vec(),
        working_dir: workdir,
        env: Default::default(),
        secret_env: Default::default(),
        connect_timeout_secs: Some(30),
        timeout_secs: Some(timeout),
    })
}

fn display(output: OutputFormat, action: &str, vm: &str, field: &str, value: Value) {
    let mut result = json!({"status": "ok", "action": action.replace(' ', "-"), "vm": vm});
    result[field] = value;
    crate::print_output(
        output,
        &result,
        serde_json::to_string_pretty(&result).unwrap(),
    );
}

pub(crate) fn agent_command(agent: &str, prompt: String) -> Vec<String> {
    let mut command: Vec<String> = ["runuser", "-u", "developer", "--"]
        .into_iter()
        .map(String::from)
        .collect();
    match agent {
        "claude" => command.extend(
            [
                "claude",
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--permission-mode",
                "acceptEdits",
            ]
            .into_iter()
            .map(String::from),
        ),
        _ => command.extend(
            ["codex", "exec", "--json", "--full-auto"]
                .into_iter()
                .map(String::from),
        ),
    }
    command.push(prompt);
    command
}

#[expect(
    clippy::too_many_arguments,
    reason = "command adapter carries the CLI session options"
)]
pub(crate) async fn start_session(
    daemon: &DaemonClient,
    name: &str,
    workdir: Option<String>,
    timeout: u64,
    env_file: Vec<PathBuf>,
    secret: Vec<String>,
    command: Vec<String>,
    output: OutputFormat,
    action: &str,
) -> Result<()> {
    segment(name)?;
    let mut request = exec_request(command, workdir, timeout)?;
    if action == "prompt" {
        request
            .env
            .insert("RUSTUP_HOME".into(), "/opt/rustup".into());
        request.env.insert("CARGO_HOME".into(), "/opt/cargo".into());
    }
    request.env.extend(
        crate::merge_env(&env_file, Vec::new())?
            .into_iter()
            .map(|s| {
                let (k, v) = s.split_once('=').expect("validated env");
                (k.to_string(), v.to_string())
            })
            .collect::<std::collections::HashMap<_, _>>(),
    );
    request.secret_env = crate::build_secret_env(&secret)?;
    let info: SessionInfo = daemon
        .execute_json(
            daemon
                .post(format!("/v1/vms/{name}/sessions"))
                .json(&request),
            "session start",
        )
        .await?;
    display(output, action, name, "session", serde_json::to_value(info)?);
    Ok(())
}

pub(crate) async fn session(
    daemon: &DaemonClient,
    name: &str,
    action: SessionAction,
    output: OutputFormat,
) -> Result<()> {
    segment(name)?;
    let base = format!("/v1/vms/{name}/sessions");
    match action {
        SessionAction::Start {
            workdir,
            timeout,
            env_file,
            secret,
            command,
        } => {
            start_session(
                daemon,
                name,
                workdir,
                timeout,
                env_file,
                secret,
                command,
                output,
                "session start",
            )
            .await
        }
        SessionAction::List => {
            let info: Vec<SessionInfo> = daemon
                .execute_json(daemon.get(&base), "session list")
                .await?;
            display(
                output,
                "session list",
                name,
                "sessions",
                serde_json::to_value(info)?,
            );
            Ok(())
        }
        SessionAction::Get { id } => {
            segment(&id)?;
            let info: SessionInfo = daemon
                .execute_json(daemon.get(format!("{base}/{id}")), "session status")
                .await?;
            display(
                output,
                "session get",
                name,
                "session",
                serde_json::to_value(info)?,
            );
            Ok(())
        }
        SessionAction::Cancel { id } => {
            segment(&id)?;
            let info: SessionInfo = daemon
                .execute_json(
                    daemon.post(format!("{base}/{id}/cancel")),
                    "session cancellation",
                )
                .await?;
            display(
                output,
                "session cancel",
                name,
                "session",
                serde_json::to_value(info)?,
            );
            Ok(())
        }
        SessionAction::Remove { id, yes } => {
            segment(&id)?;
            crate::require_confirmation(
                &format!("Remove session '{id}' and its logs?"),
                yes,
                output,
            );
            let response = daemon.send(daemon.delete(format!("{base}/{id}"))).await?;
            if !response.status().is_success() {
                return Err(daemon.error(response, "session removal").await.into());
            }
            crate::print_output(
                output,
                &json!({"status":"ok", "action":"session-remove", "vm": name}),
                "Removed session",
            );
            Ok(())
        }
    }
}

pub(crate) async fn events(
    daemon: &DaemonClient,
    name: &str,
    id: &str,
    mut after: u64,
    follow: bool,
    output: OutputFormat,
) -> Result<()> {
    segment(name)?;
    segment(id)?;
    ensure!(
        !follow || output != OutputFormat::Json,
        "events --follow streams bytes; use --output text or poll JSON pages with --after"
    );
    loop {
        let request = daemon.get(format!("/v1/vms/{name}/sessions/{id}/events?after={after}"));
        let page: SessionEventsResponse = daemon.execute_json(request, "session events").await?;
        if !follow {
            display(output, "events", name, "page", serde_json::to_value(page)?);
            return Ok(());
        }
        for event in &page.events {
            let bytes = husker_agent_proto::base64_decode(&event.data)
                .map_err(|e| anyhow::anyhow!("invalid event data: {e}"))?;
            if event.stream == "stderr" {
                std::io::stderr().write_all(&bytes)?;
                std::io::stderr().flush()?;
            } else {
                std::io::stdout().write_all(&bytes)?;
                std::io::stdout().flush()?;
            }
        }
        after = page.next_cursor;
        if page.session.state != SessionState::Running && !page.has_more {
            if page.session.output_truncated {
                eprintln!("\n[husker: retained session output reached its limit]");
            }
            ensure!(
                page.session.exit_code == Some(0),
                "session ended {:?} with exit code {:?}",
                page.session.state,
                page.session.exit_code
            );
            return Ok(());
        }
        if !page.has_more {
            tokio::select! { _ = tokio::signal::ctrl_c() => return Ok(()), _ = tokio::time::sleep(Duration::from_millis(250)) => {} }
        }
    }
}

async fn create(
    target: &DaemonTarget,
    config_path: Option<&Path>,
    name: &str,
    image: &str,
    cpus: u32,
    memory: u32,
    disk_size: String,
) -> Result<Value> {
    segment(name)?;
    let config = crate::load_config(config_path);
    let plan = plan_vm_creation(
        target.daemon(),
        &config,
        VmCreationIntent {
            name: name.into(),
            pool: None,
            profile: None,
            args: VmRequestArgs {
                rootfs: Some(image.into()),
                cpus: Some(cpus),
                memory: Some(memory),
                disk_size: Some(disk_size),
                ..Default::default()
            },
            userdata: None,
            extra_pool_conflicts: Vec::new(),
        },
        target.is_local(),
    )
    .await?;
    let response = plan
        .prepare(&config)
        .await?
        .execute(target.daemon())
        .await?;
    if !response.status().is_success() {
        return Err(target
            .daemon()
            .error(response, "development VM")
            .await
            .into());
    }
    Ok(response.json().await?)
}

async fn run_script(
    daemon: &DaemonClient,
    name: &str,
    script: &str,
    env: std::collections::HashMap<String, String>,
) -> Result<husker_api::ExecResponse> {
    let mut request = exec_request(vec!["sh".into(), "-c".into(), script.into()], None, 3600)?;
    request.env = env;
    let result = daemon.exec(name, &request).await?;
    ensure!(
        result.exit_code == 0,
        "guest setup failed (VM {name} retained for inspection):\n{}\n{}",
        result.stdout,
        result.stderr
    );
    Ok(result)
}

pub(crate) async fn development(
    target: &DaemonTarget,
    config_path: Option<&Path>,
    output: OutputFormat,
    action: DevAction,
) -> Result<()> {
    let daemon = target.daemon();
    match action {
        DevAction::Prepare {
            image,
            base,
            cpus,
            memory,
            disk_size,
            rust,
            codex,
            claude,
        } => {
            segment(&image)?;
            // Refuse before allocating a builder; image names are immutable.
            let existing = daemon
                .send(daemon.get(format!("/v1/images/{image}")))
                .await?;
            ensure!(
                existing.status() == reqwest::StatusCode::NOT_FOUND,
                "image '{image}' exists or could not be checked; choose a new versioned image name"
            );
            let name = format!("dev-builder-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            create(target, config_path, &name, &base, cpus, memory, disk_size).await?;
            let env = std::collections::HashMap::from([
                ("HUSKER_DEV_RUST_TOOLCHAIN".into(), rust),
                ("HUSKER_DEV_CODEX_VERSION".into(), codex),
                ("HUSKER_DEV_CLAUDE_VERSION".into(), claude),
            ]);
            eprintln!("Preparing image '{image}' in {name}; this downloads development tools");
            run_script(daemon, &name, PROVISION, env).await?;
            run_script(daemon, &name, START_DOCKER, Default::default()).await?;
            run_script(daemon, &name, CHECK, Default::default()).await?;
            run_script(daemon, &name, "rm -rf /var/lib/husker/sessions /root/.codex /root/.claude /home/developer/.codex /home/developer/.claude; sync", Default::default()).await?;
            let response = daemon
                .send(daemon.post(format!("/v1/vms/{name}/stop")))
                .await?;
            if !response.status().is_success() {
                return Err(daemon.error(response, "stop image builder").await.into());
            }
            let result: Value = daemon
                .execute_json(
                    daemon
                        .post(format!("/v1/vms/{name}/commit-image"))
                        .json(&json!({"name":image})),
                    "commit prepared image",
                )
                .await?;
            let response = daemon
                .send(daemon.delete(format!("/v1/vms/{name}")))
                .await?;
            if !response.status().is_success() {
                return Err(daemon.error(response, "remove image builder").await.into());
            }
            display(output, "dev prepare", &name, "result", result);
            Ok(())
        }
        DevAction::New {
            name,
            image,
            cpus,
            memory,
            disk_size,
        } => {
            let vm = create(target, config_path, &name, &image, cpus, memory, disk_size).await?;
            run_script(daemon, &name, START_DOCKER, Default::default()).await?;
            run_script(daemon, &name, CHECK, Default::default()).await?;
            display(output, "dev new", &name, "result", vm);
            Ok(())
        }
        DevAction::Check { name } => {
            segment(&name)?;
            let result = run_script(daemon, &name, CHECK, Default::default()).await?;
            display(
                output,
                "dev check",
                &name,
                "result",
                serde_json::to_value(result)?,
            );
            Ok(())
        }
    }
}

pub(crate) async fn preview(
    daemon: &DaemonClient,
    name: &str,
    port: u16,
    local_port: u16,
) -> Result<()> {
    segment(name)?;
    // Fail before printing a URL if the guest agent/service is unavailable.
    let mut probe = daemon.tunnel(name, port).await?;
    probe.close(None).await?;
    let listener =
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, local_port)).await?;
    let address = listener.local_addr()?;
    println!("http://{address}/");
    eprintln!("Private preview of {name}:{port}; Ctrl-C closes the tunnel");
    let mut relays = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            accepted = listener.accept(), if relays.len() < 64 => {
                let (tcp, _) = accepted?;
                let daemon = daemon.clone(); let name = name.to_string();
                relays.spawn(async move {
                    if let Err(error) = relay(tcp, &daemon, &name, port).await { eprintln!("preview connection: {error:#}"); }
                });
            }
            _ = relays.join_next(), if !relays.is_empty() => {},
        }
    }
    relays.shutdown().await;
    Ok(())
}

async fn relay(
    tcp: tokio::net::TcpStream,
    daemon: &DaemonClient,
    name: &str,
    port: u16,
) -> Result<()> {
    let ws = daemon.tunnel(name, port).await?;
    let (mut sink, mut source) = ws.split();
    let (mut reader, mut writer) = tcp.into_split();
    let (output, mut messages) = tokio::sync::mpsc::channel(4);
    let control = output.clone();
    let input = async {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let n = reader.read(&mut buffer).await?;
            if n == 0 {
                output.send(Message::Text("eof".into())).await?;
                // TCP write-half closure must still allow the complete response.
                return std::future::pending::<Result<()>>().await;
            }
            output
                .send(Message::Binary(buffer[..n].to_vec().into()))
                .await?;
        }
    };
    let response = async {
        while let Some(message) = source.next().await {
            match message? {
                Message::Binary(bytes) => writer.write_all(&bytes).await?,
                Message::Ping(bytes) => control.send(Message::Pong(bytes)).await?,
                Message::Pong(_) => {}
                Message::Close(_) => break,
                _ => anyhow::bail!("unexpected preview tunnel frame"),
            }
        }
        writer.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let flush = async {
        while let Some(message) = messages.recv().await {
            sink.send(message).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! { result = input => result, result = response => result, result = flush => result }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preview_relay_drains_response_while_request_is_backpressured() {
        const SIZE: usize = 8 * 1024 * 1024;
        let remote = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let daemon = DaemonClient::new(format!("http://{}", remote.local_addr().unwrap()), None);
        let upstream = tokio::spawn(async move {
            let (tcp, _) = remote.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            for _ in 0..SIZE / 16384 {
                ws.send(Message::Binary(vec![0xAB; 16384].into()))
                    .await
                    .unwrap();
            }
            let mut received = 0;
            while let Some(message) = ws.next().await {
                match message.unwrap() {
                    Message::Binary(bytes) => {
                        assert!(bytes.iter().all(|b| *b == 0xCD));
                        received += bytes.len();
                    }
                    Message::Text(text) if text == "eof" => break,
                    _ => panic!("unexpected input"),
                }
            }
            assert_eq!(received, SIZE);
            ws.close(None).await.unwrap();
        });
        let local = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let client = tokio::net::TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (tcp, _) = local.accept().await.unwrap();
        let pump = tokio::spawn(async move {
            relay(tcp, &daemon, "dev", 3000).await.unwrap();
        });
        let (mut reader, mut writer) = client.into_split();
        let send = async {
            writer.write_all(&vec![0xCD; SIZE]).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receive = async {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes.len(), SIZE);
            assert!(bytes.iter().all(|b| *b == 0xAB));
        };
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(send, receive);
            pump.await.unwrap();
            upstream.await.unwrap();
        })
        .await
        .unwrap();
    }
}
