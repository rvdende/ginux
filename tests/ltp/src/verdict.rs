//! A test's result, spelled as in the results file and `report.py`.

use std::fmt;
use std::str::FromStr;

/// The result of one test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Passed: exit status 0 and no failure printed.
    Tpass,
    /// LTP reported a failure.
    Tfail,
    /// LTP reported a break, or the test died or could not run.
    Tbrok,
    /// LTP reported the test does not apply (a configuration skip).
    Tconf,
    /// LTP reported a warning.
    Twarn,
    /// The domain, the kernel or QEMU went down during the test.
    Crash,
    /// The test ran past its time budget.
    Hang,
    /// Marked skipped in the run list.
    Skip,
    /// Not reached: the run was interrupted or gave up.
    Notrun,
}

impl Verdict {
    /// Every result, in the order of the results file's summary line.
    pub const ALL: [Verdict; 9] = [
        Verdict::Tpass,
        Verdict::Tfail,
        Verdict::Tbrok,
        Verdict::Tconf,
        Verdict::Twarn,
        Verdict::Crash,
        Verdict::Hang,
        Verdict::Skip,
        Verdict::Notrun,
    ];

    /// The name used in the results file.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Tpass => "TPASS",
            Verdict::Tfail => "TFAIL",
            Verdict::Tbrok => "TBROK",
            Verdict::Tconf => "TCONF",
            Verdict::Twarn => "TWARN",
            Verdict::Crash => "CRASH",
            Verdict::Hang => "HANG",
            Verdict::Skip => "SKIP",
            Verdict::Notrun => "NOTRUN",
        }
    }

    /// The position in [`Verdict::ALL`], for counting.
    pub fn index(self) -> usize {
        self as usize
    }

    /// Whether the test ran and did not pass: a result the baseline records.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Verdict::Tfail | Verdict::Tbrok | Verdict::Twarn | Verdict::Crash | Verdict::Hang
        )
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Verdict {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Verdict::ALL
            .into_iter()
            .find(|verdict| verdict.as_str() == text)
            .ok_or_else(|| format!("unknown result {text:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_in_summary_order() {
        let names: Vec<_> = Verdict::ALL.iter().map(|v| v.to_string()).collect();
        assert_eq!(
            names,
            ["TPASS", "TFAIL", "TBROK", "TCONF", "TWARN", "CRASH", "HANG", "SKIP", "NOTRUN"]
        );
        for (index, verdict) in Verdict::ALL.into_iter().enumerate() {
            assert_eq!(verdict.as_str().parse::<Verdict>(), Ok(verdict));
            assert_eq!(verdict.index(), index);
        }
        assert!("PASS".parse::<Verdict>().is_err());
    }

    #[test]
    fn failures_are_the_results_that_ran_and_did_not_pass() {
        let failing: Vec<_> = Verdict::ALL
            .into_iter()
            .filter(|v| v.is_failure())
            .collect();
        assert_eq!(
            failing,
            [
                Verdict::Tfail,
                Verdict::Tbrok,
                Verdict::Twarn,
                Verdict::Crash,
                Verdict::Hang
            ]
        );
    }
}
