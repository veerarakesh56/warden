//! CLI integration tests — spawn the compiled `helios` binary and inspect stdout.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Locate helios-ai/.venv/{Scripts|bin}/python for the e2e test, or None if absent.
fn venv_python(root: &std::path::Path) -> Option<PathBuf> {
    for rel in [
        "helios-ai/.venv/Scripts/python.exe",
        "helios-ai/.venv/bin/python",
    ] {
        let p = root.join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// The venv interpreter, or None after printing "skipping". With `HELIOS_REQUIRE_PY=1` (set in CI) a
/// missing venv panics instead, so the Python e2e tests cannot pass by silently not running.
fn venv_python_or_skip(root: &std::path::Path) -> Option<PathBuf> {
    let python = venv_python(root);
    if python.is_none() {
        assert!(
            std::env::var("HELIOS_REQUIRE_PY").as_deref() != Ok("1"),
            "HELIOS_REQUIRE_PY=1 but helios-ai/.venv is missing — run `uv sync` in helios-ai/"
        );
        eprintln!("skipping: helios-ai/.venv not found — run `uv sync` in helios-ai/");
    }
    python
}

#[test]
fn simulate_json_emits_failure_chain_as_json() {
    let root = repo_root();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args([
            "simulate",
            "fixtures/three-tier-webapp",
            "--scenario",
            "fixtures/scenarios/az-outage.yaml",
            "--json",
        ])
        .output()
        .expect("failed to spawn helios");

    // az-outage produces failures → non-zero exit
    assert!(
        !output.status.success(),
        "expected non-zero exit on failures"
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout not valid JSON: {e}\nstdout: {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });

    assert_eq!(parsed["scenario"], "lose-us-east-1a");
    assert!(parsed["failures"].is_array());
    assert!(
        parsed["failures"].as_array().unwrap().len() >= 3,
        "expected at least 3 failures, got {:?}",
        parsed["failures"]
    );
}

#[test]
fn explain_subcommand_pipes_stdin_to_python() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let root = repo_root();
    let Some(python) = venv_python_or_skip(&root) else {
        return;
    };

    let chain = r#"{"scenario":"e2e-test","failures":[]}"#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .arg("explain")
        .env("HELIOS_AI_PYTHON", &python)
        .env("HELIOS_AI_MOCK", "1")
        .env_remove("ANTHROPIC_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn helios explain");

    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(chain.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("wait helios explain");
    assert!(
        output.status.success(),
        "helios explain failed: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("e2e-test") && stdout.contains("mocked"),
        "expected mock narrative mentioning scenario, got: {stdout}"
    );
}

#[test]
fn propose_fix_subcommand_emits_valid_fix_json_via_mock() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let root = repo_root();
    let Some(python) = venv_python_or_skip(&root) else {
        return;
    };

    let payload = r#"{"chain":{"scenario":"lose-us-east-1a","failures":[{"id":"aws_elasticache_cluster.cache","kind":"ElasticacheCluster","reason":"single-AZ in us-east-1a, which is down"}]},"attrs_snapshot":{"aws_elasticache_cluster.cache":{"availability_zone":"us-east-1a"}}}"#;

    let mut child = Command::new(&python)
        .args(["-m", "helios_ai", "propose-fix"])
        .current_dir(root.join("helios-ai"))
        .env("HELIOS_AI_MOCK", "1")
        .env_remove("ANTHROPIC_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn helios_ai propose-fix");

    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(payload.as_bytes())
        .unwrap();

    let output = child
        .wait_with_output()
        .expect("wait helios_ai propose-fix");
    assert!(
        output.status.success(),
        "propose-fix failed: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout not valid JSON: {e}\nstdout: {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(parsed["scenario_name"], "lose-us-east-1a");
    let edits = parsed["edits"].as_array().expect("edits is array");
    assert!(!edits.is_empty(), "expected at least one edit");
    assert_eq!(edits[0]["op"], "set_attr");
}

#[test]
fn helios_propose_fix_simulates_and_prints_a_fix_proposal_via_mock() {
    let root = repo_root();
    let Some(python) = venv_python_or_skip(&root) else {
        return;
    };
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args([
            "propose-fix",
            "fixtures/three-tier-webapp",
            "--scenario",
            "fixtures/scenarios/az-outage.yaml",
        ])
        .env("HELIOS_AI_PYTHON", &python)
        .env("HELIOS_AI_MOCK", "1")
        .env_remove("ANTHROPIC_API_KEY")
        .output()
        .expect("spawn helios propose-fix");
    assert!(
        output.status.success(),
        "helios propose-fix failed: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout not a FixProposal: {e}\nstdout: {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    // The mock targets the chain's first failure, so this proves the simulated chain reached it.
    assert_eq!(parsed["scenario_name"], "lose-us-east-1a");
    assert_eq!(
        parsed["edits"][0]["resource_id"],
        "aws_elasticache_cluster.cache"
    );
}

#[test]
fn helios_propose_fix_with_nothing_failing_prints_nothing_and_calls_no_model() {
    let root = repo_root();
    let tmp = tempfile::tempdir().unwrap();
    let scenario = tmp.path().join("c.yaml");
    std::fs::write(
        &scenario,
        "name: lose-1c\nkind:\n  type: az-outage\n  az: us-east-1c\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args(["propose-fix", "fixtures/three-tier-webapp", "--scenario"])
        .arg(&scenario)
        // A python that does not exist: reaching it would fail the command.
        .env("HELIOS_AI_PYTHON", tmp.path().join("no-python"))
        .output()
        .expect("spawn helios propose-fix");
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nothing to fix"));
}

#[test]
fn verify_with_resolving_fix_reports_resolved_section() {
    let root = repo_root();
    let tmp = tempfile::tempdir().unwrap();
    let fix_path = tmp.path().join("fix.json");
    std::fs::write(
        &fix_path,
        r#"{
            "scenario_name": "lose-us-east-1a",
            "explanation": "move cache to us-east-1b",
            "edits": [
                {"op":"set_attr","resource_id":"aws_elasticache_cluster.cache","key":"availability_zone","value":"us-east-1b"}
            ]
        }"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args([
            "verify",
            "fixtures/three-tier-webapp",
            "--scenario",
            "fixtures/scenarios/az-outage.yaml",
            "--fix",
        ])
        .arg(&fix_path)
        .output()
        .expect("failed to spawn helios verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Resolved") && stdout.contains("aws_elasticache_cluster.cache"),
        "expected Resolved section naming cache; got:\n{stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Some failures remain (subnet + instance), so exit code is non-zero.
    assert!(
        !output.status.success(),
        "expected non-zero exit (remaining failures)"
    );
}

/// The shipped fix moves every us-east-1a resource to us-east-1b: its own scenario comes out clean,
/// a 1b outage takes 5 resources instead of 1. That is a regression, and verify must exit 1.
#[test]
fn verify_fails_a_fix_that_moves_the_damage_to_another_zone() {
    let root = repo_root();
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_helios"))
            .current_dir(&root)
            .args([
                "verify",
                "fixtures/three-tier-webapp",
                "--scenario",
                "fixtures/scenarios/az-outage.yaml",
                "--fix",
                "fixes/az-outage.json",
            ])
            .args(extra)
            .output()
            .expect("spawn helios verify")
    };
    let output = run(&[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("Verdict: NEW FAILURES INTRODUCED in az-outage us-east-1b"),
        "{stdout}"
    );

    let output = run(&["--json"]);
    assert_eq!(output.status.code(), Some(1));
    let doc: Value = serde_json::from_slice(&output.stdout).expect("verify --json is JSON");
    assert_eq!(doc["verdict"], "new-failures");
    assert_eq!(doc["fix_scenario"], "lose-us-east-1a");
    let scenarios = doc["scenarios"].as_array().unwrap();
    assert_eq!(scenarios[0]["scenario"], "lose-us-east-1a");
    assert_eq!(scenarios[0]["target"], true);
    assert_eq!(scenarios[0]["post_fix"]["failures"], serde_json::json!([]));
    let b = scenarios
        .iter()
        .find(|s| s["scenario"] == "az-outage us-east-1b")
        .expect("1b checked");
    assert_eq!(b["pre_fix"]["failures"].as_array().unwrap().len(), 1);
    assert_eq!(b["post_fix"]["failures"].as_array().unwrap().len(), 5);
}

/// What the Action runs when the caller names no scenarios: one file per zone, region and NAT.
#[test]
fn scenarios_writes_the_standard_set_for_the_plan() {
    let root = repo_root();
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args(["scenarios", "fixtures/wave4-fullstack/plan.json", "--out"])
        .arg(tmp.path())
        .output()
        .expect("spawn helios scenarios");
    assert!(output.status.success(), "{output:?}");
    let mut names: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "az-outage-ap-south-2a.yaml",
            "az-outage-ap-south-2b.yaml",
            "region-outage-ap-south-2.yaml",
            "single-nat-death-aws-nat-gateway-this.yaml"
        ]
    );
    let nat = std::fs::read_to_string(
        tmp.path()
            .join("single-nat-death-aws-nat-gateway-this.yaml"),
    )
    .unwrap();
    assert!(nat.contains("type: single-nat-death") && nat.contains("aws_nat_gateway.this"));
}

#[test]
fn verify_rejects_a_fix_written_for_another_scenario() {
    let root = repo_root();
    let tmp = tempfile::tempdir().unwrap();
    let fix_path = tmp.path().join("fix.json");
    std::fs::write(
        &fix_path,
        r#"{"scenario_name":"something-else","explanation":"x","edits":[{"op":"set_attr","resource_id":"aws_elasticache_cluster.cache","key":"availability_zone","value":"us-east-1b"}]}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args([
            "verify",
            "fixtures/three-tier-webapp",
            "--scenario",
            "fixtures/scenarios/az-outage.yaml",
            "--fix",
        ])
        .arg(&fix_path)
        .output()
        .expect("spawn helios verify");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("something-else") && stderr.contains("lose-us-east-1a"),
        "{stderr}"
    );
}

#[test]
fn verify_rejects_fix_naming_unknown_resource() {
    let root = repo_root();
    let tmp = tempfile::tempdir().unwrap();
    let fix_path = tmp.path().join("bad.json");
    std::fs::write(
        &fix_path,
        r#"{"scenario_name":"lose-us-east-1a","explanation":"x","edits":[{"op":"set_attr","resource_id":"aws_nope.ghost","key":"foo","value":1}]}"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args([
            "verify",
            "fixtures/three-tier-webapp",
            "--scenario",
            "fixtures/scenarios/az-outage.yaml",
            "--fix",
        ])
        .arg(&fix_path)
        .output()
        .expect("spawn helios verify");

    assert!(
        !output.status.success(),
        "expected non-zero exit on unknown resource"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown resource") || stderr.contains("aws_nope.ghost"),
        "expected unknown-resource error; stderr: {stderr}"
    );
}

#[test]
fn inspect_emits_combined_graph_and_chain_json() {
    let root = repo_root();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args([
            "inspect",
            "fixtures/three-tier-webapp",
            "--scenario",
            "fixtures/scenarios/az-outage.yaml",
        ])
        .output()
        .expect("failed to spawn helios inspect");

    assert!(
        output.status.success(),
        "inspect should exit 0 even with failures present; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout not valid JSON: {e}\nstdout: {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });

    assert_eq!(parsed["scenario"], "lose-us-east-1a");
    assert!(parsed["graph"]["nodes"].is_array());
    assert!(parsed["graph"]["edges"].is_array());
    assert!(parsed["chain"]["failures"].is_array());

    let nodes = parsed["graph"]["nodes"].as_array().unwrap();
    let edges = parsed["graph"]["edges"].as_array().unwrap();
    assert!(!nodes.is_empty(), "expected nodes, got empty");
    assert!(!edges.is_empty(), "expected edges, got empty");

    // Schema spot-checks: nodes have id/kind/attrs, edges have from/to/dep with kind+via.
    assert!(nodes[0]["id"].is_string());
    assert!(nodes[0]["kind"].is_string());
    assert!(edges[0]["dep"]["kind"].is_string());
    assert!(edges[0]["dep"]["via"].is_string());
}

#[test]
fn plan_says_whether_it_read_a_state_or_a_plan() {
    let root = repo_root();
    for (input, source) in [
        ("fixtures/three-tier-webapp", "source: state"),
        ("fixtures/wave4-synthetic/plan.json", "source: plan"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_helios"))
            .current_dir(&root)
            .args(["plan", input])
            .output()
            .expect("failed to spawn helios plan");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.starts_with(source), "{input}: {stdout}");
    }
}

#[test]
fn an_inconclusive_scenario_exits_3_with_nothing_on_stdout() {
    let root = repo_root();
    for cmd in ["simulate", "inspect"] {
        let output = Command::new(env!("CARGO_BIN_EXE_helios"))
            .current_dir(&root)
            .args([
                cmd,
                "fixtures/iam-inconclusive/plan.json",
                "--scenario",
                "fixtures/iam-inconclusive/revoke-worker.yaml",
            ])
            .output()
            .expect("spawn helios");
        assert_eq!(output.status.code(), Some(3), "{cmd}");
        assert!(output.stdout.is_empty(), "{cmd}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("INCONCLUSIVE (not a pass)"));
    }
}

#[test]
fn warnings_are_plain_text_and_a_subnet_placed_instance_is_not_called_unplaceable() {
    // stderr is a pipe here, as in CI and the Action: no ANSI colour codes. p1b's instances have
    // no zone of their own but a subnet with one -- they are placed, so no "ZONE UNKNOWN" line.
    let root = repo_root();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args(["plan", "fixtures/edge-cases/p1b.json"])
        .output()
        .expect("spawn helios plan");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("WARN"), "expected warnings: {stderr}");
    assert!(!stderr.contains('\u{1b}'), "ANSI escapes in: {stderr}");
    assert!(!stderr.contains("AVAILABILITY ZONE UNKNOWN"), "{stderr}");
}

#[test]
fn a_warning_is_printed_once_however_often_the_attribute_is_resolved() {
    let root = repo_root();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args(["plan", "fixtures/edge-cases/vpc-plan-foreach.json"])
        .output()
        .expect("spawn helios plan");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Drop the timestamp; the rest of each line must be unique.
    let lines: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("WARN"))
        .map(|l| l.split_once(' ').map_or(l, |(_, rest)| rest))
        .collect();
    let unique: std::collections::BTreeSet<&str> = lines.iter().copied().collect();
    assert!(lines.len() > 1, "{stderr}");
    assert_eq!(lines.len(), unique.len(), "repeated warnings:\n{stderr}");
}

#[test]
fn unsupported_types_are_summarised_in_one_line() {
    // wave4-synthetic has an aws_internet_gateway and an aws_sns_topic Helios does not model.
    let root = repo_root();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args(["plan", "fixtures/wave4-synthetic/terraform-show.json"])
        .output()
        .expect("spawn helios plan");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let summaries: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("unsupported types (not in the graph"))
        .collect();
    assert_eq!(summaries.len(), 1, "{stderr}");
    assert!(
        summaries[0].contains(
            "skipped 2 resources of 2 unsupported types (not in the graph, not assumed \
             healthy): aws_internet_gateway (1), aws_sns_topic (1)"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("skipping unsupported"), "{stderr}");
}

/// Unsupported resources are listed in the JSON, counted on stderr whatever the log level, and
/// `--fail-on-unsupported` turns them into exit 3 with nothing on stdout.
#[test]
fn unsupported_resources_are_listed_counted_and_can_be_made_inconclusive() {
    let root = repo_root();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_helios"))
            .current_dir(&root)
            .args(args)
            .args([
                "fixtures/wave4-synthetic/terraform-show.json",
                "--scenario",
                "fixtures/wave4-fullstack/scenarios/az-2a.yaml",
                "--log-level",
                "off",
            ])
            .output()
            .expect("spawn helios")
    };
    let want = serde_json::json!([
        {"type": "aws_internet_gateway", "count": 1, "addresses": ["aws_internet_gateway.this"]},
        {"type": "aws_sns_topic", "count": 1, "addresses": ["aws_sns_topic.order_events"]}
    ]);
    for cmd in [vec!["simulate", "--json"], vec!["inspect"]] {
        let output = run(&cmd);
        let doc: Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
        assert_eq!(doc["skipped"], want, "{cmd:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("NOT SIMULATED: 2 resource(s) of 2 unsupported type(s)"),
            "{cmd:?}: {stderr}"
        );
    }
    assert_eq!(
        run(&["inspect"]).status.code(),
        Some(0),
        "default unchanged"
    );
    for cmd in [vec!["simulate", "--json"], vec!["inspect"]] {
        let mut args = vec!["--fail-on-unsupported"];
        args.extend(cmd.iter());
        let output = run(&args);
        assert_eq!(output.status.code(), Some(3), "{cmd:?}");
        assert!(output.stdout.is_empty(), "{cmd:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("INCONCLUSIVE (not a pass)"));
    }
}

#[test]
fn simulate_plain_still_works() {
    let root = repo_root();
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .current_dir(&root)
        .args([
            "simulate",
            "fixtures/three-tier-webapp",
            "--scenario",
            "fixtures/scenarios/az-outage.yaml",
        ])
        .output()
        .expect("failed to spawn helios");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("lose-us-east-1a") || stdout.contains("FAIL") || stdout.contains("aws_"),
        "plain render should mention the scenario or failures; got: {stdout}"
    );
}

/// Locks the three-tier outputs: every refactor must reproduce these bytes (CRLF-normalised, so a
/// Windows checkout with autocrlf still compares). Regenerate only for a deliberate, disclosed change.
#[test]
fn three_tier_outputs_are_byte_identical() {
    let root = repo_root();
    let golden = root.join("crates/helios-cli/tests/golden/three-tier");
    for scenario in [
        "az-outage",
        "iam-revocation",
        "region-outage",
        "resource-loss",
        "single-nat-death",
        "slow-rds-failover",
    ] {
        let scenario_path = format!("fixtures/scenarios/{scenario}.yaml");
        for (cmd, args) in [
            ("inspect", vec!["inspect"]),
            ("simulate", vec!["simulate", "--json"]),
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_helios"))
                .current_dir(&root)
                .args(&args)
                .args(["fixtures/three-tier-webapp", "--scenario", &scenario_path])
                .output()
                .expect("failed to spawn helios");
            let want = std::fs::read_to_string(golden.join(format!("{scenario}.{cmd}.json")))
                .expect("golden file")
                .replace("\r\n", "\n");
            let got = String::from_utf8(output.stdout)
                .expect("utf-8 stdout")
                .replace("\r\n", "\n");
            assert_eq!(
                got,
                want,
                "{scenario} {cmd} drifted from its golden; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
