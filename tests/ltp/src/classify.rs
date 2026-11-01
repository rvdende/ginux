//! Turns the runner's END status and a test's console output into a result.

use std::sync::LazyLock;

use regex::bytes::Regex;

use crate::Verdict;

/// The LTP result kinds a test prints, each with the pattern that finds a
/// result line of that kind: from the new LTP API ("file.c:12: TFAIL: ...")
/// or the old one ("name    1  TFAIL  :  ...").
static PRINTED: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    ["TPASS", "TFAIL", "TBROK", "TWARN", "TCONF"]
        .into_iter()
        .map(|kind| {
            let pattern = format!(r"(?m-u)(?:\.c:\d+: |^\S+\s+\d+\s+){kind}\b");
            (kind, Regex::new(&pattern).expect("valid result pattern"))
        })
        .collect()
});

fn printed(kind: &str) -> &'static Regex {
    PRINTED
        .iter()
        .find(|(name, _)| *name == kind)
        .map(|(_, pattern)| pattern)
        .expect("a known result kind")
}

/// Whether the test printed a `kind` result line (TPASS, TFAIL, TBROK, TWARN
/// or TCONF).
pub fn printed_result(output: &[u8], kind: &str) -> bool {
    printed(kind).is_match(output)
}

/// The message of the first `kind` result line the test printed, without
/// its source position: "syscall not supported" from
/// "foo.c:12: TCONF: syscall not supported".
pub fn first_message(output: &[u8], kind: &str) -> Option<String> {
    let found = printed(kind).find(output)?;
    let rest = &output[found.end()..];
    let line = &rest[..memchr::memchr(b'\n', rest).unwrap_or(rest.len())];
    let message = String::from_utf8_lossy(line);
    let message = message.trim_start_matches([' ', '\t', ':']).trim_end();
    (!message.is_empty()).then(|| message.to_string())
}

fn contains(output: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(output, needle).is_some()
}

/// Maps the runner's END status (`exit=N`, `signal=N`, `timeout`,
/// `lost:...`) and the test's output to a result and its detail.
pub fn classify(status: &str, output: &[u8], budget: u32) -> (Verdict, String) {
    if status == "timeout" {
        return (Verdict::Hang, format!("guest-timeout {budget}s"));
    }
    if status.starts_with("lost") {
        return (
            Verdict::Tbrok,
            format!("runner lost the test's exit status ({status})"),
        );
    }
    if let Some(signal) = status.strip_prefix("signal=") {
        return (Verdict::Tbrok, format!("killed by signal {signal}"));
    }
    let Some(code) = status
        .strip_prefix("exit=")
        .and_then(|code| code.parse::<i64>().ok())
    else {
        return (Verdict::Tbrok, status.to_string());
    };
    // LTP's library also kills the test when a child reports TBROK; it then
    // prints the same "Test killed!" line, but that is a break, not a hang.
    if contains(output, b"reported TBROK killing the test") {
        return (Verdict::Tbrok, format!("{status} (a child reported TBROK)"));
    }
    if contains(output, b"Test killed! (timeout?)") {
        return (Verdict::Hang, format!("ltp-timeout {status}"));
    }
    if code == 0 {
        // The LTP library counts results in a page it shares with the test
        // process and derives the exit status from it. Under Ginux that page
        // has not always reached the library's process from the test, so the
        // exit status can claim success after the test reported a failure:
        // the results it printed decide.
        // LTP's rule: any break, failure or warning marks the test; skips
        // (TCONF) only when nothing passed.
        for (kind, verdict) in [
            ("TBROK", Verdict::Tbrok),
            ("TFAIL", Verdict::Tfail),
            ("TWARN", Verdict::Twarn),
        ] {
            if printed_result(output, kind) {
                return (verdict, format!("{status} ({kind} printed)"));
            }
        }
        if printed_result(output, "TCONF") && !printed_result(output, "TPASS") {
            return (Verdict::Tconf, format!("{status} (TCONF printed)"));
        }
        return (Verdict::Tpass, status.to_string());
    }
    if code == 126 || code == 127 {
        return (Verdict::Tbrok, format!("{status} (could not execute)"));
    }
    if code >= 128 {
        // An exit status of 128+N from a test usually means a signal killed
        // something it waited for.
        return (
            Verdict::Tbrok,
            format!(
                "{status} (signal {} reported as an exit status?)",
                code - 128
            ),
        );
    }
    if code > 63 {
        return (Verdict::Tbrok, format!("{status} (not an LTP result)"));
    }
    if code & 2 != 0 {
        return (Verdict::Tbrok, status.to_string());
    }
    if code & 1 != 0 {
        return (Verdict::Tfail, status.to_string());
    }
    if code & 4 != 0 {
        return (Verdict::Twarn, status.to_string());
    }
    if code & 32 != 0 {
        return (Verdict::Tconf, status.to_string());
    }
    (Verdict::Tbrok, format!("{status} (no LTP result bits)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(status: &str, output: &str) -> (Verdict, String) {
        classify(status, output.as_bytes(), 60)
    }

    #[test]
    fn runner_statuses() {
        assert_eq!(
            check("timeout", ""),
            (Verdict::Hang, "guest-timeout 60s".into())
        );
        assert_eq!(
            check("lost:wait=-1,errno=10", ""),
            (
                Verdict::Tbrok,
                "runner lost the test's exit status (lost:wait=-1,errno=10)".into()
            )
        );
        assert_eq!(
            check("signal=9", ""),
            (Verdict::Tbrok, "killed by signal 9".into())
        );
        assert_eq!(
            check("fork-errno=11", ""),
            (Verdict::Tbrok, "fork-errno=11".into())
        );
        assert_eq!(
            check("status=1407", ""),
            (Verdict::Tbrok, "status=1407".into())
        );
        assert_eq!(check("exit=x", ""), (Verdict::Tbrok, "exit=x".into()));
    }

    #[test]
    fn exit_status_bits_in_precedence_order() {
        assert_eq!(check("exit=0", ""), (Verdict::Tpass, "exit=0".into()));
        assert_eq!(check("exit=1", ""), (Verdict::Tfail, "exit=1".into()));
        assert_eq!(check("exit=2", ""), (Verdict::Tbrok, "exit=2".into()));
        assert_eq!(check("exit=3", ""), (Verdict::Tbrok, "exit=3".into()));
        assert_eq!(check("exit=4", ""), (Verdict::Twarn, "exit=4".into()));
        assert_eq!(check("exit=5", ""), (Verdict::Tfail, "exit=5".into()));
        assert_eq!(check("exit=32", ""), (Verdict::Tconf, "exit=32".into()));
        assert_eq!(check("exit=36", ""), (Verdict::Twarn, "exit=36".into()));
        assert_eq!(
            check("exit=8", ""),
            (Verdict::Tbrok, "exit=8 (no LTP result bits)".into())
        );
        assert_eq!(
            check("exit=64", ""),
            (Verdict::Tbrok, "exit=64 (not an LTP result)".into())
        );
        assert_eq!(
            check("exit=126", ""),
            (Verdict::Tbrok, "exit=126 (could not execute)".into())
        );
        assert_eq!(
            check("exit=127", ""),
            (Verdict::Tbrok, "exit=127 (could not execute)".into())
        );
        assert_eq!(
            check("exit=137", ""),
            (
                Verdict::Tbrok,
                "exit=137 (signal 9 reported as an exit status?)".into()
            )
        );
    }

    #[test]
    fn ltp_timeouts_and_child_breaks() {
        let killed = "tst_test.c:1700: TINFO: Test killed! (timeout?)\n";
        assert_eq!(
            check("exit=2", killed),
            (Verdict::Hang, "ltp-timeout exit=2".into())
        );
        let child = "tst_test.c:1600: TBROK: Child (12) reported TBROK killing the test\n\
                     tst_test.c:1700: TINFO: Test killed! (timeout?)\n";
        assert_eq!(
            check("exit=2", child),
            (Verdict::Tbrok, "exit=2 (a child reported TBROK)".into())
        );
    }

    #[test]
    fn printed_results_decide_a_zero_exit() {
        let both = "foo.c:10: TPASS: ok\r\nfoo.c:11: TFAIL: bad\r\n";
        assert_eq!(
            check("exit=0", both),
            (Verdict::Tfail, "exit=0 (TFAIL printed)".into())
        );
        let warn_and_break = "foo.c:10: TWARN: w\nfoo.c:11: TBROK: b\n";
        assert_eq!(
            check("exit=0", warn_and_break),
            (Verdict::Tbrok, "exit=0 (TBROK printed)".into())
        );
        let warn = "foo.c:10: TWARN: w\n";
        assert_eq!(
            check("exit=0", warn),
            (Verdict::Twarn, "exit=0 (TWARN printed)".into())
        );
        let conf = "foo.c:10: TCONF: not here\n";
        assert_eq!(
            check("exit=0", conf),
            (Verdict::Tconf, "exit=0 (TCONF printed)".into())
        );
        let conf_and_pass = "foo.c:10: TCONF: not here\nfoo.c:12: TPASS: fine\n";
        assert_eq!(
            check("exit=0", conf_and_pass),
            (Verdict::Tpass, "exit=0".into())
        );
        // A non-zero exit is decided by its bits, not by what was printed.
        assert_eq!(check("exit=32", both), (Verdict::Tconf, "exit=32".into()));
    }

    #[test]
    fn recognizes_both_ltp_apis_and_nothing_else() {
        assert!(printed_result(b"tst_test.c:12: TFAIL: x", "TFAIL"));
        assert!(printed_result(
            b"intro\nabort01    1  TFAIL  :  abort01.c:90: x\n",
            "TFAIL"
        ));
        assert!(printed_result(
            b"intro\r\nabort01    1  TFAIL  :  x\r\n",
            "TFAIL"
        ));
        assert!(!printed_result(b"foo.c:12: TFAILED", "TFAIL"));
        assert!(!printed_result(b"the word TFAIL in prose", "TFAIL"));
        assert!(!printed_result(
            b"foo.c:12: TINFO: TFAIL would be bad",
            "TFAIL"
        ));
        assert!(!printed_result(b"foo.c:12:TFAIL", "TFAIL"));
        // Invalid UTF-8 does not hide a result line.
        assert!(printed_result(b"\xff\xfe\nx 3 TBROK : y", "TBROK"));
    }

    #[test]
    fn first_message_strips_the_position() {
        let output =
            b"a.c:1: TINFO: hi\na.c:2: TCONF: syscall not supported\r\na.c:3: TCONF: second\n";
        assert_eq!(
            first_message(output, "TCONF").as_deref(),
            Some("syscall not supported")
        );
        let old = b"getxattr02    1  TCONF  :  getxattr02.c:60: no xattr support\n";
        assert_eq!(
            first_message(old, "TCONF").as_deref(),
            Some("getxattr02.c:60: no xattr support")
        );
        assert_eq!(first_message(b"a.c:1: TCONF:\n", "TCONF"), None);
        assert_eq!(first_message(b"nothing", "TCONF"), None);
    }
}
