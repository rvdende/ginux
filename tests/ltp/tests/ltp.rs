//! The LTP harness's test target: one libtest trial per entry of the run
//! list, all run by one QEMU session (see `src/lib.rs` and docs/LTP.md).
//!
//! libtest's arguments select trials as usual (a name filter, `--exact`,
//! `--skip`, `--ignored`, `--list`, `-q`); only the selected tests run in
//! the guest. The harness's own settings come from the environment
//! (`LTP_LIST`, `LTP_TESTS`, `LTP_FILTER`, `LTP_VARIANT`, `GINUX_ESP_DIR`,
//! ...; `src/config.rs`), plus two switches: `--strict` (report every
//! failure, ignoring the baseline) and `--update-baseline`.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use ginux_ltp::baseline::{outcome, Baseline, Outcome, Report};
use ginux_ltp::config::Config;
use ginux_ltp::list::{parse_list, select, Test};
use ginux_ltp::progress::{Format, Progress};
use ginux_ltp::session::{new_volume, serve_guest_files, Run};
use ginux_ltp::Verdict;
use libtest_mimic::{Arguments, Completion, Failed, FormatSetting, Trial};

fn main() -> ExitCode {
    match harness() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// What libtest's arguments make of a test.
enum Plan {
    /// Filtered out by name: not run and not in the results.
    Filtered,
    /// Ignored by libtest (`--bench`): never called.
    Idle,
    /// Marked skipped in the list: ignored, with the reason (`--ignored`
    /// and `--include-ignored` run it instead).
    Skip(String),
    /// Runs in the guest.
    Guest,
}

fn harness() -> Result<ExitCode, String> {
    let mut strict = false;
    let mut update_baseline = false;
    let argv: Vec<OsString> = env::args_os()
        .filter(|arg| match arg.to_str() {
            Some("--strict") => {
                strict = true;
                false
            }
            Some("--update-baseline") => {
                update_baseline = true;
                false
            }
            _ => true,
        })
        .collect();
    let mut args = Arguments::from_iter(argv);
    // One QEMU session runs the tests in list order, so results arrive in
    // that order.
    args.test_threads = Some(1);

    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let repo = repo.canonicalize().unwrap_or(repo);
    let config = Arc::new(Config::from_env(repo, strict, update_baseline)?);
    let source = config.display(&config.list);
    let text = fs::read_to_string(&config.list)
        .map_err(|error| format!("cannot read {}: {error}", config.list.display()))?;
    let all = parse_list(&text, &source, config.default_budget)?;
    let list_order: Vec<String> = all.iter().map(|test| test.tag.clone()).collect();
    let tests = select(all, &config.tests, &config.filter, &source)?;

    // Skipped tests are libtest's ignored tests: with --ignored or
    // --include-ignored they run.
    let run_ignored = args.ignored || args.include_ignored;
    let flagged = |test: &Test| test.skip.is_some() && run_ignored;
    let plans: Vec<Plan> = tests
        .iter()
        .map(|test| {
            let probe = Trial::test(test.tag.clone(), || Ok(())).with_ignored_flag(flagged(test));
            if args.is_filtered_out(&probe) {
                Plan::Filtered
            } else if args.is_ignored(&probe) {
                Plan::Idle
            } else {
                match &test.skip {
                    Some(reason) if !run_ignored => Plan::Skip(reason.clone()),
                    _ => Plan::Guest,
                }
            }
        })
        .collect();
    let runnable = plans
        .iter()
        .filter(|plan| matches!(plan, Plan::Guest))
        .count();

    let quiet_trial = |test: &Test, plan: &Plan| match plan {
        Plan::Skip(reason) => {
            let reason = format!("SKIP: {reason}");
            Trial::ignorable_test(test.tag.clone(), move || {
                Ok(Completion::ignored_with(reason))
            })
        }
        _ => {
            Trial::test(test.tag.clone(), || Err("not run".into())).with_ignored_flag(flagged(test))
        }
    };
    if args.list || runnable == 0 {
        let trials = tests
            .iter()
            .zip(&plans)
            .map(|(test, plan)| quiet_trial(test, plan))
            .collect();
        return Ok(libtest_mimic::run(&args, trials).exit_code());
    }

    let ltp_dir = config.ltp_dir();
    for required in ["ltp.tar.xz", "ltp-runner"] {
        if !ltp_dir.join(required).is_file() {
            let variant = if config.variant.is_empty() {
                String::new()
            } else {
                format!(" (tools/ltp/build.sh --variant {})", config.variant)
            };
            return Err(format!(
                "Missing {}; run 'make ltp'{variant} first.",
                ltp_dir.join(required).display()
            ));
        }
    }
    if !config.esp_dir.join("EFI/BOOT/BOOTX64.EFI").is_file() {
        return Err(format!(
            "Missing {}/EFI/BOOT/BOOTX64.EFI; run 'make build' first.",
            config.esp_dir.display()
        ));
    }
    let baseline = Arc::new(match fs::read_to_string(&config.baseline) {
        Ok(text) => Baseline::parse(&text, &config.display(&config.baseline))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if !config.strict {
                eprintln!(
                    "ltp: no baseline at {}; every failure is a regression",
                    config.baseline.display()
                );
            }
            Baseline::default()
        }
        Err(error) => {
            return Err(format!(
                "cannot read {}: {error}",
                config.baseline.display()
            ))
        }
    });

    // The run: every test libtest did not filter out; the guest runs those
    // planned for it, in list order.
    let kept: Vec<(&Test, &Plan)> = tests
        .iter()
        .zip(&plans)
        .filter(|(_, plan)| !matches!(plan, Plan::Filtered))
        .collect();
    let guest: Vec<usize> = kept
        .iter()
        .enumerate()
        .filter(|(_, (_, plan))| matches!(plan, Plan::Guest))
        .map(|(index, _)| index)
        .collect();
    let run_tests: Vec<Test> = kept.iter().map(|(test, _)| (*test).clone()).collect();
    let guest_tests: Vec<&Test> = guest.iter().map(|&index| &run_tests[index]).collect();
    let name_width = run_tests
        .iter()
        .map(|test| test.tag.chars().count())
        .max()
        .unwrap_or(0);

    fs::create_dir_all(config.work()).map_err(failed("create the work directory"))?;
    new_volume(&config.volume()).map_err(failed("create the volume"))?;
    let base_url =
        serve_guest_files(&config, &guest_tests).map_err(failed("serve the LTP files"))?;
    let format = match (args.quiet, args.format) {
        (true, _) | (_, Some(FormatSetting::Terse)) => Format::Terse,
        (_, Some(FormatSetting::Json)) => Format::Json,
        _ => Format::Pretty,
    };
    let progress = Progress::new(runnable, format, name_width, args.logfile.is_some());
    let interrupted = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(&interrupted))
            .map_err(failed("handle SIGINT and SIGTERM"))?;
    }
    let skipped = run_tests.len() - runnable;
    let (run, receivers) = Run::new(
        Arc::clone(&config),
        run_tests,
        list_order,
        guest,
        Arc::clone(&progress),
        interrupted,
    )
    .map_err(failed("start the run"))?;
    progress.message(&format!(
        "ltp: {runnable} tests to run, {skipped} skipped; results in {}, serial log in {}",
        config.results().display(),
        config.serial_log().display()
    ));

    let on_interrupt = {
        let baseline = Arc::clone(&baseline);
        move |run: &Run| {
            run.summarize(&baseline);
            std::process::exit(1);
        }
    };
    let session = run.spawn(base_url, on_interrupt);

    let mut receivers = receivers.into_iter();
    let trials: Vec<Trial> = tests
        .iter()
        .zip(&plans)
        .map(|(test, plan)| match plan {
            Plan::Guest => {
                let receiver = receivers.next().expect("a receiver for each guest test");
                let known = if config.strict {
                    None
                } else {
                    baseline.get(&test.tag)
                };
                let log = config.display(&config.logs().join(format!("{}.log", test.tag)));
                guest_trial(test, receiver, known, Arc::clone(&progress), log)
                    .with_ignored_flag(flagged(test))
            }
            other => quiet_trial(test, other),
        })
        .collect();
    let conclusion = libtest_mimic::run(&args, trials);
    let run = session
        .join()
        .map_err(|_| "ltp: the session thread panicked".to_string())?;
    run.summarize(&baseline);
    Ok(conclusion.exit_code())
}

/// An error message for a failed setup step.
fn failed(what: &'static str) -> impl Fn(io::Error) -> String {
    move |error| format!("ltp: cannot {what}: {error}")
}

/// A trial that waits for its test's result from the session.
fn guest_trial(
    test: &Test,
    receiver: Receiver<Report>,
    known: Option<Verdict>,
    progress: Arc<Progress>,
    log: String,
) -> Trial {
    let name = test.tag.clone();
    Trial::ignorable_test(test.tag.clone(), move || {
        progress.trial_waits(&name);
        let report = receiver
            .recv()
            .unwrap_or_else(|_| Report::not_reached("the session ended unexpectedly"));
        progress.trial_returns();
        match outcome(&report, known, &log) {
            Outcome::Pass => Ok(Completion::Completed),
            Outcome::Ignore(reason) => Ok(Completion::ignored_with(reason)),
            Outcome::Fail(message) => Err(Failed::from(message)),
        }
    })
}
