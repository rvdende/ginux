//! The baseline: tests known not to pass (`tests/ltp/baseline.txt`), and
//! how a test's result maps to a libtest outcome against it.

use std::collections::{HashMap, HashSet};

use crate::Verdict;

/// The comment that heads a baseline file written by the harness.
const HEADER: &str = "\
# LTP tests known not to pass on Ginux, one `NAME RESULT` per line
# (docs/LTP.md). A listed test that fails again is reported as ignored
# (\"known failure\"); a failure of any other test is a regression and fails
# the run. Rewrite it from a run with LTP_UPDATE_BASELINE=1
# (tests/qemu/ltp.sh --update-baseline); LTP_STRICT=1 ignores it.
";

/// Tests known not to pass, with the result each last had, in file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Baseline {
    entries: Vec<(String, Verdict)>,
    index: HashMap<String, usize>,
}

impl Baseline {
    /// Parses `NAME RESULT` lines; `#` starts a comment line.
    pub fn parse(text: &str, source: &str) -> Result<Self, String> {
        let mut baseline = Baseline::default();
        for (number, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [name, result] = fields[..] else {
                return Err(format!(
                    "{source}:{}: expected NAME RESULT: {raw}",
                    number + 1
                ));
            };
            let verdict: Verdict = result
                .parse()
                .map_err(|error| format!("{source}:{}: {error}", number + 1))?;
            if !verdict.is_failure() {
                return Err(format!(
                    "{source}:{}: {verdict} is not a failure; only failing tests belong in the baseline",
                    number + 1
                ));
            }
            if baseline.get(name).is_some() {
                return Err(format!("{source}:{}: duplicate test {name}", number + 1));
            }
            baseline.insert(name, verdict);
        }
        Ok(baseline)
    }

    /// The result `name` is known to fail with, if it is in the baseline.
    pub fn get(&self, name: &str) -> Option<Verdict> {
        self.index.get(name).map(|&at| self.entries[at].1)
    }

    /// The number of known failures.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no failure is known.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The known failures, in order.
    pub fn entries(&self) -> &[(String, Verdict)] {
        &self.entries
    }

    fn insert(&mut self, name: &str, verdict: Verdict) {
        self.index.insert(name.to_string(), self.entries.len());
        self.entries.push((name.to_string(), verdict));
    }

    /// The baseline after a run: each test that ran and failed is recorded
    /// with its new result, each that passed or was a configuration skip
    /// (TCONF) is dropped, and tests that did not run (SKIP, NOTRUN, or not
    /// selected) keep their entries. Entries are in `order` (the run list),
    /// followed by entries for tests not in it, in their old order.
    pub fn updated<'a>(
        &self,
        order: impl IntoIterator<Item = &'a str>,
        results: &HashMap<String, Verdict>,
    ) -> Baseline {
        let result_of = |name: &str| match results.get(name) {
            Some(verdict) if verdict.is_failure() => Some(*verdict),
            Some(Verdict::Tpass | Verdict::Tconf) => None,
            _ => self.get(name),
        };
        let mut updated = Baseline::default();
        let mut listed = HashSet::new();
        for name in order {
            listed.insert(name);
            if let Some(verdict) = result_of(name) {
                updated.insert(name, verdict);
            }
        }
        for (name, _) in &self.entries {
            if !listed.contains(name.as_str()) {
                if let Some(verdict) = result_of(name) {
                    updated.insert(name, verdict);
                }
            }
        }
        updated
    }

    /// The file text: the header, a line naming the run it came from, then
    /// one `NAME RESULT` per line.
    pub fn render(&self, origin: &str) -> String {
        let mut text = format!("{HEADER}# {origin}\n");
        for (name, verdict) in &self.entries {
            text.push_str(&format!("{name} {verdict}\n"));
        }
        text
    }
}

/// How a trial ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The test passed.
    Pass,
    /// Reported as ignored, with the reason.
    Ignore(String),
    /// The trial failed, with the message.
    Fail(String),
}

/// What a trial needs to know about its test's result.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    /// The result.
    pub verdict: Verdict,
    /// How long the test ran, in seconds.
    pub seconds: f64,
    /// The result's detail, as in the results file.
    pub detail: String,
    /// The first TCONF message the test printed, for a TCONF result.
    pub conf_reason: Option<String>,
    /// The end of the test's console log.
    pub log_tail: String,
}

impl Report {
    /// A test the run did not reach.
    pub fn not_reached(why: &str) -> Self {
        Report {
            verdict: Verdict::Notrun,
            seconds: 0.0,
            detail: format!("not reached ({why})"),
            conf_reason: None,
            log_tail: String::new(),
        }
    }
}

/// Maps a test's result to the trial's outcome. `known` is the test's
/// baseline result (always `None` in strict mode); `log` names its log.
pub fn outcome(report: &Report, known: Option<Verdict>, log: &str) -> Outcome {
    let verdict = report.verdict;
    match verdict {
        Verdict::Tpass => Outcome::Pass,
        Verdict::Tconf => Outcome::Ignore(match &report.conf_reason {
            Some(reason) => format!("TCONF: {}", shorten(reason, 100)),
            None => format!("TCONF: {}", report.detail),
        }),
        Verdict::Skip => Outcome::Ignore(format!("SKIP: {}", report.detail)),
        Verdict::Notrun => Outcome::Fail(format!("NOTRUN: {}", report.detail)),
        _ => match known {
            Some(known) if known == verdict => Outcome::Ignore(format!("known failure: {verdict}")),
            Some(known) => Outcome::Ignore(format!("known failure: {verdict}, was {known}")),
            None => {
                let mut message = format!(
                    "{verdict} after {:.2}s: {}\nlog: {log}",
                    report.seconds, report.detail
                );
                if !report.log_tail.is_empty() {
                    message.push_str("\n--- end of the log ---\n");
                    message.push_str(report.log_tail.trim_end());
                }
                Outcome::Fail(message)
            }
        },
    }
}

/// The last `count` lines of `log`.
pub fn tail_lines(log: &[u8], count: usize) -> String {
    let text = String::from_utf8_lossy(log);
    let lines: Vec<&str> = text.trim_end().lines().collect();
    lines[lines.len().saturating_sub(count)..].join("\n")
}

fn shorten(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((cut, _)) => format!("{}...", &text[..cut]),
        None => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(verdict: Verdict) -> Report {
        Report {
            verdict,
            seconds: 1.5,
            detail: "exit=1".to_string(),
            conf_reason: None,
            log_tail: "line 1\nline 2".to_string(),
        }
    }

    #[test]
    fn parses_names_and_failing_results() {
        let text = "# comment\n\nabort01 TFAIL\nfork14 HANG\n  connect01   HANG  \n";
        let baseline = Baseline::parse(text, "b").unwrap();
        assert_eq!(baseline.len(), 3);
        assert_eq!(baseline.get("fork14"), Some(Verdict::Hang));
        assert_eq!(baseline.get("connect01"), Some(Verdict::Hang));
        assert_eq!(baseline.get("accept01"), None);
        assert!(Baseline::parse("a TFAIL extra\n", "b").is_err());
        assert!(Baseline::parse("a\n", "b").is_err());
        assert!(Baseline::parse("a FAIL\n", "b").is_err());
        assert_eq!(
            Baseline::parse("x TPASS\n", "b").unwrap_err(),
            "b:1: TPASS is not a failure; only failing tests belong in the baseline"
        );
        assert_eq!(
            Baseline::parse("a TFAIL\na TBROK\n", "b").unwrap_err(),
            "b:2: duplicate test a"
        );
    }

    #[test]
    fn renders_what_it_parses() {
        let baseline = Baseline::parse("b TBROK\na CRASH\n", "b").unwrap();
        let text = baseline.render("from a test");
        assert!(text.starts_with("# LTP tests known not to pass"));
        assert!(text.ends_with("# from a test\nb TBROK\na CRASH\n"));
        assert_eq!(Baseline::parse(&text, "b").unwrap(), baseline);
    }

    #[test]
    fn update_keeps_what_did_not_run() {
        let old = Baseline::parse(
            "gone TFAIL\nfixed TFAIL\nchanged TFAIL\nidle HANG\nconf TBROK\n",
            "b",
        )
        .unwrap();
        let results: HashMap<String, Verdict> = [
            ("fixed", Verdict::Tpass),
            ("changed", Verdict::Crash),
            ("new", Verdict::Twarn),
            ("conf", Verdict::Tconf),
            ("idle", Verdict::Notrun),
            ("skipped", Verdict::Skip),
            ("fine", Verdict::Tpass),
        ]
        .into_iter()
        .map(|(name, verdict)| (name.to_string(), verdict))
        .collect();
        let order = ["new", "fixed", "changed", "idle", "conf", "skipped", "fine"];
        let updated = old.updated(order, &results);
        let entries: Vec<_> = updated
            .entries()
            .iter()
            .map(|(n, v)| (n.as_str(), *v))
            .collect();
        assert_eq!(
            entries,
            [
                ("new", Verdict::Twarn),
                ("changed", Verdict::Crash),
                ("idle", Verdict::Hang),
                ("gone", Verdict::Tfail),
            ]
        );
    }

    #[test]
    fn outcomes() {
        assert_eq!(outcome(&report(Verdict::Tpass), None, "l"), Outcome::Pass);
        assert_eq!(
            outcome(&report(Verdict::Tpass), Some(Verdict::Tfail), "l"),
            Outcome::Pass
        );
        assert_eq!(
            outcome(&report(Verdict::Tconf), None, "l"),
            Outcome::Ignore("TCONF: exit=1".into())
        );
        let mut conf = report(Verdict::Tconf);
        conf.conf_reason = Some("no libnuma".into());
        assert_eq!(
            outcome(&conf, None, "l"),
            Outcome::Ignore("TCONF: no libnuma".into())
        );
        let mut skip = report(Verdict::Skip);
        skip.detail = "needs a loop device".into();
        assert_eq!(
            outcome(&skip, None, "l"),
            Outcome::Ignore("SKIP: needs a loop device".into())
        );
        assert_eq!(
            outcome(&report(Verdict::Tfail), Some(Verdict::Tfail), "l"),
            Outcome::Ignore("known failure: TFAIL".into())
        );
        assert_eq!(
            outcome(&report(Verdict::Hang), Some(Verdict::Tbrok), "l"),
            Outcome::Ignore("known failure: HANG, was TBROK".into())
        );
        assert_eq!(
            outcome(&report(Verdict::Tbrok), None, "target/ltp/logs/x.log"),
            Outcome::Fail(
                "TBROK after 1.50s: exit=1\nlog: target/ltp/logs/x.log\n--- end of the log ---\nline 1\nline 2"
                    .into()
            )
        );
        assert_eq!(
            outcome(
                &Report::not_reached("interrupted"),
                Some(Verdict::Tfail),
                "l"
            ),
            Outcome::Fail("NOTRUN: not reached (interrupted)".into())
        );
    }

    #[test]
    fn tails_and_shortening() {
        let log = b"1\n2\n3\n4\n\n";
        assert_eq!(tail_lines(log, 2), "3\n4");
        assert_eq!(tail_lines(log, 10), "1\n2\n3\n4");
        assert_eq!(tail_lines(b"", 3), "");
        assert_eq!(shorten("abcdef", 3), "abc...");
        assert_eq!(shorten("abc", 3), "abc");
    }
}
