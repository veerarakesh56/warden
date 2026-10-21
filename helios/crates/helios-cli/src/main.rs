use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "helios",
    version,
    about = "Deterministic failure simulation for cloud infrastructure"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    /// Exit 3 (inconclusive) when the input has resources of types Helios does not model. Off by
    /// default: they are skipped, counted on stderr and listed under `skipped` in JSON output.
    #[arg(long, global = true)]
    fail_on_unsupported: bool,
}

/// `--fail-on-unsupported`, set once in `main`.
static FAIL_ON_UNSUPPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// [`helios_graph::load_full`], saying on stderr -- whatever the log level -- how many resources
/// were NOT simulated, and exiting [`EXIT_INCONCLUSIVE`] for them under `--fail-on-unsupported`.
fn load(input: &std::path::Path) -> Result<helios_graph::Loaded> {
    let loaded = helios_graph::load_full(input)?;
    let n: usize = loaded.skipped.iter().map(|s| s.count).sum();
    if n > 0 {
        eprintln!(
            "helios: NOT SIMULATED: {n} resource(s) of {} unsupported type(s), next to {} \
             modelled -- they are absent from the graph, not assumed healthy (listed under \
             `skipped` in JSON output)",
            loaded.skipped.len(),
            loaded.graph.node_count()
        );
        if FAIL_ON_UNSUPPORTED.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!(
                "helios: INCONCLUSIVE (not a pass): --fail-on-unsupported and {n} resource(s) \
                 cannot be simulated"
            );
            std::process::exit(EXIT_INCONCLUSIVE);
        }
    }
    Ok(loaded)
}

/// A JSON document with the input's `skipped` list appended, field order kept.
#[derive(serde::Serialize)]
struct WithSkipped<'a, T: serde::Serialize> {
    #[serde(flatten)]
    doc: &'a T,
    skipped: &'a [helios_graph::Skipped],
}

fn print_json<T: serde::Serialize>(doc: &T, skipped: &[helios_graph::Skipped]) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout().lock(), &WithSkipped { doc, skipped })?;
    println!();
    Ok(())
}

#[derive(Subcommand)]
enum Command {
    /// Parse a Terraform JSON input (`terraform show -json` of a state or of a saved plan) and
    /// summarise the resource graph.
    Plan {
        /// Path to a directory containing terraform-show.json, or to the JSON file itself.
        input: PathBuf,
    },
    /// Run a failure scenario against the resource graph.
    Simulate {
        input: PathBuf,
        #[arg(long)]
        scenario: PathBuf,
        /// Emit FailureChain as JSON on stdout instead of plain text.
        #[arg(long)]
        json: bool,
    },
    /// Re-run simulation with a proposed fix applied: the fix's own scenario, every other
    /// `--scenario` given, and every zone, region and NAT outage of the graph. Exits 0 only when
    /// the fix's scenario is clean and NO scenario fails anywhere it did not before.
    Verify {
        input: PathBuf,
        /// Scenario YAML; repeatable. One must be the scenario the fix names (`scenario_name`).
        #[arg(long, required = true)]
        scenario: Vec<PathBuf>,
        #[arg(long)]
        fix: PathBuf,
        /// Emit the per-scenario report as JSON on stdout instead of plain text.
        #[arg(long)]
        json: bool,
    },
    /// Emit a combined `{graph, chain}` JSON document for the web viewer / GitHub Action.
    Inspect {
        input: PathBuf,
        #[arg(long)]
        scenario: PathBuf,
    },
    /// Write the standard scenarios for a graph (an az-outage per zone, a region-outage per
    /// region, a single-nat-death per NAT gateway) as YAML files into `--out`; prints each path.
    Scenarios {
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Narrate a FailureChain (read as JSON on stdin) via the helios-ai Python shell.
    Explain,
    /// Simulate, then ask helios-ai for a FixProposal (JSON on stdout, ready for `verify --fix`).
    /// Only the FAILED resources' attributes are sent, with sensitive values redacted.
    ProposeFix {
        input: PathBuf,
        #[arg(long)]
        scenario: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // stderr, NOT stdout. `simulate --json` and `inspect` write a document to stdout that the
    // GitHub Action redirects to a file and parses with `jq`; a warning on stdout corrupts it, so
    // one skipped resource would break the PR comment on any real repository.
    // No colour codes unless a person is watching: CI logs, the Action's captured stderr and
    // `2> file` must stay plain text.
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(tracing_subscriber::EnvFilter::new(&cli.log_level))
        .init();
    FAIL_ON_UNSUPPORTED.store(
        cli.fail_on_unsupported,
        std::sync::atomic::Ordering::Relaxed,
    );

    match cli.command {
        Command::Plan { input } => cmd_plan(&input),
        Command::Simulate {
            input,
            scenario,
            json,
        } => cmd_simulate(&input, &scenario, json),
        Command::Verify {
            input,
            scenario,
            fix,
            json,
        } => cmd_verify(&input, &scenario, &fix, json),
        Command::Inspect { input, scenario } => cmd_inspect(&input, &scenario),
        Command::Scenarios { input, out } => cmd_scenarios(&input, &out),
        Command::Explain => cmd_explain(),
        Command::ProposeFix { input, scenario } => cmd_propose_fix(&input, &scenario),
    }
}

fn cmd_plan(input: &std::path::Path) -> Result<()> {
    let loaded = load(input)?;
    println!("source: {}", loaded.source);
    println!(
        "loaded {} resources, {} dependency edges",
        loaded.graph.node_count(),
        loaded.graph.edge_count()
    );
    let skipped: usize = loaded.skipped.iter().map(|s| s.count).sum();
    if skipped > 0 {
        println!("skipped {skipped} resources of unsupported types (not simulated)");
    }
    Ok(())
}

fn cmd_simulate(input: &std::path::Path, scenario: &std::path::Path, json: bool) -> Result<()> {
    let loaded = load(input)?;
    let scenario = helios_engine::scenario::load(scenario)
        .map_err(|e| anyhow::anyhow!("loading scenario: {e}"))?;
    let chain = simulate(&loaded.graph, &scenario)?;
    if json {
        print_json(&chain, &loaded.skipped)?;
    } else {
        print!("{}", chain.render_plain());
    }
    if !chain.is_safe() {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_verify(
    input: &std::path::Path,
    scenarios: &[PathBuf],
    fix: &std::path::Path,
    json: bool,
) -> Result<()> {
    let loaded = load(input)?;
    let graph = &loaded.graph;
    let scenarios = scenarios
        .iter()
        .map(|p| helios_engine::scenario::load(p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("loading scenario: {e}"))?;
    let fix = helios_engine::fix::load(fix).map_err(|e| anyhow::anyhow!("loading fix: {e}"))?;
    let report = helios_engine::verify(graph, &scenarios, &fix).map_err(|e| {
        if let helios_engine::VerifyError::Simulate(inner) = &e {
            exit_if_inconclusive(inner);
        }
        anyhow::anyhow!("verify: {e}")
    })?;
    let verdict = report.verdict();

    if json {
        let doc = serde_json::json!({
            "fix_scenario": fix.scenario_name,
            "verdict": verdict,
            "scenarios": report.scenarios,
        });
        print_json(&doc, &loaded.skipped)?;
    } else {
        print!("{}", render_verify(&report));
    }
    match verdict {
        helios_engine::Verdict::Resolved => Ok(()),
        helios_engine::Verdict::Inconclusive => std::process::exit(EXIT_INCONCLUSIVE),
        _ => std::process::exit(1),
    }
}

fn render_verify(report: &helios_engine::VerifyReport) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Fix for: {} (checked against {} scenarios)",
        report.target().scenario,
        report.scenarios.len()
    );
    let count = |c: &Option<helios_engine::FailureChain>| {
        c.as_ref()
            .map_or("inconclusive".to_string(), |c| c.failures.len().to_string())
    };
    for s in &report.scenarios {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Scenario: {}{}",
            s.scenario,
            if s.target {
                " [the fix's scenario]"
            } else {
                ""
            }
        );
        let _ = writeln!(out, "Pre-fix failures:  {}", count(&s.pre_fix));
        let _ = writeln!(out, "Post-fix failures: {}", count(&s.post_fix));
        if let Some(why) = &s.inconclusive {
            let _ = writeln!(out, "  INCONCLUSIVE (not a pass): {why}");
        }
        for (title, tag, ids) in [
            ("Resolved", "[OK]", &s.resolved),
            ("New failures introduced", "[NEW]", &s.new_failures),
            ("Still failing", "[--]", &s.remaining),
        ] {
            if !ids.is_empty() {
                let _ = writeln!(out, "  {title} ({}):", ids.len());
                for id in ids {
                    let _ = writeln!(out, "    {tag} {id}");
                }
            }
        }
    }
    let worse: Vec<&str> = report
        .scenarios
        .iter()
        .filter(|s| !s.new_failures.is_empty())
        .map(|s| s.scenario.as_str())
        .collect();
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Verdict: {}",
        match report.verdict() {
            helios_engine::Verdict::NewFailures =>
                format!("NEW FAILURES INTRODUCED in {}", worse.join(", ")),
            helios_engine::Verdict::StillFailing =>
                "STILL FAILING: the fix's scenario has failures left".to_string(),
            helios_engine::Verdict::Inconclusive =>
                "INCONCLUSIVE: a scenario could not be evaluated (not a pass)".to_string(),
            helios_engine::Verdict::Resolved =>
                "RESOLVED: the fix's scenario is clean and nothing else got worse".to_string(),
        }
    );
    out
}

fn cmd_inspect(input: &std::path::Path, scenario: &std::path::Path) -> Result<()> {
    let loaded = load(input)?;
    let scenario = helios_engine::scenario::load(scenario)
        .map_err(|e| anyhow::anyhow!("loading scenario: {e}"))?;
    let chain = simulate(&loaded.graph, &scenario)?;
    let doc = helios_engine::build_inspect(&loaded.graph, chain);
    print_json(&doc, &loaded.skipped)
}

fn cmd_scenarios(input: &std::path::Path, out: &std::path::Path) -> Result<()> {
    let graph = load(input)?.graph;
    let scenarios = helios_engine::standard_scenarios(&[&graph]);
    if scenarios.is_empty() {
        anyhow::bail!(
            "nothing in {} declares a zone, region or NAT gateway",
            input.display()
        );
    }
    std::fs::create_dir_all(out)?;
    let names: Vec<&str> = scenarios.iter().map(|s| s.name.as_str()).collect();
    for (s, stem) in scenarios.iter().zip(scenario_stems(&names)) {
        let path = out.join(format!("{stem}.yaml"));
        std::fs::write(&path, serde_yaml_ng::to_string(s)?)?;
        println!("{}", path.display());
    }
    Ok(())
}

/// File stems for scenario names: non-alphanumerics become `-`. Names that would share a stem
/// (`aws_nat_gateway.a_b` / `aws_nat_gateway.a-b`) all get `-<FNV-1a of the full name>` appended,
/// so no file overwrites another and a stem does not depend on which name came first.
fn scenario_stems(names: &[&str]) -> Vec<String> {
    let plain = |n: &str| -> String {
        n.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect()
    };
    let fnv = |n: &str| {
        n.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        })
    };
    let mut seen = std::collections::HashMap::<String, usize>::new();
    for n in names {
        *seen.entry(plain(n)).or_default() += 1;
    }
    let stems: Vec<String> = names
        .iter()
        .map(|n| match plain(n) {
            p if seen[&p] > 1 => format!("{p}-{:016x}", fnv(n)),
            p => p,
        })
        .collect();
    let unique: std::collections::HashSet<&String> = stems.iter().collect();
    assert_eq!(
        unique.len(),
        stems.len(),
        "scenario file stems collide: {stems:?}"
    );
    stems
}

/// Exit code for a scenario Helios cannot evaluate: distinct from 0 (resilient) and 1 (failures,
/// or an error), so a pipeline cannot read "cannot say" as either.
const EXIT_INCONCLUSIVE: i32 = 3;

/// [`helios_engine::simulate()`], exiting [`EXIT_INCONCLUSIVE`] on an inconclusive scenario.
fn simulate(
    graph: &helios_graph::ResourceGraph,
    scenario: &helios_engine::Scenario,
) -> Result<helios_engine::FailureChain> {
    helios_engine::simulate(graph, scenario).map_err(|e| {
        exit_if_inconclusive(&e);
        anyhow::anyhow!("simulate: {e}")
    })
}

fn exit_if_inconclusive(e: &helios_engine::SimulateError) {
    if matches!(e, helios_engine::SimulateError::Inconclusive(_)) {
        eprintln!("helios: {e}");
        std::process::exit(EXIT_INCONCLUSIVE);
    }
}

/// Narrate a FailureChain read as JSON on stdin, via `python -m helios_ai explain`.
fn cmd_explain() -> Result<()> {
    use std::io::Read;

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| anyhow::anyhow!("reading FailureChain JSON from stdin: {e}"))?;
    // Windows PowerShell 5.1 prefixes a byte-order mark to what it pipes into a native command.
    run_helios_ai("explain", input.trim_start_matches('\u{feff}'))
}

/// Simulate, then pipe `{chain, attrs_snapshot}` to `python -m helios_ai propose-fix`, whose
/// FixProposal JSON goes straight to stdout.
fn cmd_propose_fix(input: &std::path::Path, scenario: &std::path::Path) -> Result<()> {
    let graph = load(input)?.graph;
    let scenario = helios_engine::scenario::load(scenario)
        .map_err(|e| anyhow::anyhow!("loading scenario: {e}"))?;
    let chain = simulate(&graph, &scenario)?;
    if chain.is_safe() {
        // Nothing on stdout: a pipeline into `verify --fix` must not receive a proposal for nothing.
        eprintln!("no failures under {} — nothing to fix", chain.scenario);
        return Ok(());
    }
    run_helios_ai("propose-fix", &fix_request(&graph, &chain).to_string())
}

/// The propose-fix request: the chain, and the scrubbed attrs of the resources in it — not the
/// whole graph, which is more than the model needs and more than should leave the machine.
fn fix_request(
    graph: &helios_graph::ResourceGraph,
    chain: &helios_engine::FailureChain,
) -> serde_json::Value {
    let attrs_snapshot: serde_json::Map<String, serde_json::Value> = chain
        .failures
        .iter()
        .filter_map(|f| {
            let idx = graph.node_indices().find(|i| graph[*i].id == f.id)?;
            Some((f.id.clone(), helios_engine::scrub_resource(&graph[idx])))
        })
        .collect();
    serde_json::json!({ "chain": chain, "attrs_snapshot": attrs_snapshot })
}

/// The interpreter that has `helios_ai` installed: `HELIOS_AI_PYTHON` if set, else the repo venv
/// (`helios-ai/.venv`, relative to the working directory) if it exists, else `python` on PATH.
fn helios_ai_python() -> PathBuf {
    if let Some(p) = std::env::var_os("HELIOS_AI_PYTHON") {
        return PathBuf::from(p);
    }
    for rel in [
        "helios-ai/.venv/Scripts/python.exe",
        "helios-ai/.venv/bin/python",
    ] {
        let p = PathBuf::from(rel);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("python")
}

/// Run `python -m helios_ai <sub>`, writing `stdin` to it and passing its stdout/stderr through.
/// Fails if the process cannot be spawned or exits non-zero.
fn run_helios_ai(sub: &str, stdin: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let python = helios_ai_python();
    let shown = python.display();
    let mut child = Command::new(&python)
        .args(["-m", "helios_ai", sub])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!(
                "spawning `{shown} -m helios_ai {sub}` — is helios-ai installed? Set HELIOS_AI_PYTHON \
                 or create helios-ai/.venv ({e})"
            )
        })?;

    // Drop the pipe after writing so the child sees EOF.
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(stdin.as_bytes())?;

    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("`{shown} -m helios_ai {sub}` failed: {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_stems_never_collide() {
        let names = [
            "single-nat-death aws_nat_gateway.a_b",
            "single-nat-death aws_nat_gateway.a-b",
            r#"single-nat-death aws_nat_gateway.n["a.b"]"#,
            r#"single-nat-death aws_nat_gateway.n["a_b"]"#,
            "az-outage us-east-1a",
        ];
        let stems = scenario_stems(&names);
        let unique: std::collections::HashSet<&String> = stems.iter().collect();
        assert_eq!(unique.len(), names.len(), "{stems:?}");
        assert_eq!(
            stems[4], "az-outage-us-east-1a",
            "a unique name keeps its plain stem"
        );
        assert!(stems[0].starts_with("single-nat-death-aws-nat-gateway-a-b-"));
        // Deterministic, and independent of order.
        let mut rev = names;
        rev.reverse();
        let mut again = scenario_stems(&rev);
        again.reverse();
        assert_eq!(again, stems);
    }

    #[test]
    fn the_fix_request_carries_only_the_failed_resources_scrubbed() {
        let graph = helios_graph::from_json(
            r#"{"format_version":"1.0","values":{"root_module":{"resources":[
              {"address":"aws_db_instance.db","type":"aws_db_instance",
               "values":{"id":"db","availability_zone":"us-east-1a","password":"hunter2",
                 "note":"postgres://app:fake-pw-3@db"},
               "sensitive_values":{"note":true}},
              {"address":"aws_s3_bucket.b","type":"aws_s3_bucket","values":{"id":"b"}}]}}}"#,
        )
        .unwrap();
        let chain = helios_engine::FailureChain {
            scenario: "s".into(),
            failures: vec![helios_engine::FailedResource {
                id: "aws_db_instance.db".into(),
                kind: "DbInstance".into(),
                reason: "r".into(),
            }],
        };
        let req = fix_request(&graph, &chain);
        let snapshot = req["attrs_snapshot"].as_object().unwrap();
        assert_eq!(
            snapshot.keys().collect::<Vec<_>>(),
            vec!["aws_db_instance.db"]
        );
        assert_eq!(
            snapshot["aws_db_instance.db"]["password"],
            helios_engine::REDACTED
        );
        assert_eq!(
            snapshot["aws_db_instance.db"]["availability_zone"],
            "us-east-1a"
        );
        assert_eq!(
            snapshot["aws_db_instance.db"]["note"],
            helios_engine::REDACTED
        );
        assert!(!req.to_string().contains("hunter2") && !req.to_string().contains("fake-pw-3"));
        assert_eq!(req["chain"]["scenario"], "s");
    }
}
