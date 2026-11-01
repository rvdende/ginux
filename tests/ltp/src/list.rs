//! The run list (`tests/ltp/syscalls.list`) and test selection.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

static LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(!?)(\S+)\s+([^#]*?)\s*(?:#\s*(.*))?$").expect("valid run list pattern")
});
static BUDGET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bbudget=(\d+)\b").expect("valid budget pattern"));

/// One entry of the run list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Test {
    /// The test's name, unique in the list.
    pub tag: String,
    /// The command line the runner runs (`sh -c "exec COMMAND"`).
    pub command: String,
    /// Seconds the test may run before the runner kills it.
    pub budget: u32,
    /// The reason, for a test marked skipped in the list.
    pub skip: Option<String>,
}

/// Parses a run list: `[!]TAG COMMAND [ARG...] [# NOTE]`.
///
/// `!` marks a test skipped, with NOTE as the reason; `budget=N` in NOTE
/// sets the test's time budget in seconds. `source` names the list in
/// error messages.
pub fn parse_list(text: &str, source: &str, default_budget: u32) -> Result<Vec<Test>, String> {
    let mut tests = Vec::new();
    let mut seen = HashSet::new();
    for (number, raw) in text.lines().enumerate() {
        let lineno = number + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let captures = LINE
            .captures(line)
            .filter(|captures| !captures[3].is_empty())
            .ok_or_else(|| format!("{source}:{lineno}: cannot parse: {raw}"))?;
        let tag = captures[2].to_string();
        if !seen.insert(tag.clone()) {
            return Err(format!("{source}:{lineno}: duplicate test {tag}"));
        }
        let mut note = captures.get(4).map_or("", |m| m.as_str()).to_string();
        let mut budget = default_budget;
        if let Some(found) = BUDGET.captures(&note) {
            budget = found[1]
                .parse()
                .map_err(|_| format!("{source}:{lineno}: budget out of range: {raw}"))?;
            let whole = found.get(0).expect("group 0 always matches");
            note = format!("{}{}", &note[..whole.start()], &note[whole.end()..])
                .trim()
                .to_string();
        }
        let skip = (!captures[1].is_empty()).then(|| {
            if note.is_empty() {
                "skipped".to_string()
            } else {
                note
            }
        });
        tests.push(Test {
            tag,
            command: captures[3].to_string(),
            budget,
            skip,
        });
    }
    Ok(tests)
}

/// Keeps the tests named in `names` (space-separated; all when empty) whose
/// name matches the regular expression `filter` (all when empty), in list
/// order. Naming a test that is not in the list is an error, and so is
/// selecting nothing.
pub fn select(
    tests: Vec<Test>,
    names: &str,
    filter: &str,
    source: &str,
) -> Result<Vec<Test>, String> {
    let mut tests = tests;
    let wanted: HashSet<&str> = names.split_whitespace().collect();
    if !wanted.is_empty() {
        let known: HashSet<&str> = tests.iter().map(|test| test.tag.as_str()).collect();
        let mut unknown: Vec<&str> = wanted.difference(&known).copied().collect();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            return Err(format!("Not in {source}: {}", unknown.join(" ")));
        }
        tests.retain(|test| wanted.contains(test.tag.as_str()));
    }
    if !filter.is_empty() {
        let pattern =
            Regex::new(filter).map_err(|error| format!("bad filter {filter:?}: {error}"))?;
        tests.retain(|test| pattern.is_match(&test.tag));
    }
    if tests.is_empty() {
        return Err("No tests selected.".to_string());
    }
    Ok(tests)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "\
# LTP syscall tests
abort01 abort01

accept01 accept01  # budget=90
!acct02 acct02  # needs a loop device
!bind01 bind01
fork14 fork14 -a 1  # budget=120 slow on KVM
!dirty dirtyc0w  # budget=30 auto: kernel modules
";

    fn parse(text: &str) -> Result<Vec<Test>, String> {
        parse_list(text, "test.list", 60)
    }

    #[test]
    fn parses_tags_commands_budgets_and_skips() {
        let tests = parse(LIST).unwrap();
        let summary: Vec<_> = tests
            .iter()
            .map(|t| {
                (
                    t.tag.as_str(),
                    t.command.as_str(),
                    t.budget,
                    t.skip.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("abort01", "abort01", 60, None),
                ("accept01", "accept01", 90, None),
                ("acct02", "acct02", 60, Some("needs a loop device")),
                ("bind01", "bind01", 60, Some("skipped")),
                ("fork14", "fork14 -a 1", 120, None),
                ("dirty", "dirtyc0w", 30, Some("auto: kernel modules")),
            ]
        );
    }

    #[test]
    fn rejects_a_line_without_a_command() {
        let error = parse("abort01\n").unwrap_err();
        assert_eq!(error, "test.list:1: cannot parse: abort01");
        let error = parse("ok ok\nbad   # only a note\n").unwrap_err();
        assert_eq!(error, "test.list:2: cannot parse: bad   # only a note");
    }

    #[test]
    fn rejects_duplicate_tags() {
        let error = parse("a a\nb b\na a -x\n").unwrap_err();
        assert_eq!(error, "test.list:3: duplicate test a");
    }

    #[test]
    fn budget_needs_word_boundaries() {
        let tests = parse("a a  # overbudget=5\nb b # budget=7x\n").unwrap();
        assert_eq!(tests[0].budget, 60);
        assert_eq!(tests[1].budget, 60);
    }

    #[test]
    fn selects_by_name_and_regex_in_list_order() {
        let tests = parse(LIST).unwrap();
        let names = |tests: Vec<Test>| tests.into_iter().map(|t| t.tag).collect::<Vec<_>>();
        assert_eq!(
            names(select(tests.clone(), "fork14 abort01", "", "l").unwrap()),
            ["abort01", "fork14"]
        );
        assert_eq!(
            names(select(tests.clone(), "", "^a", "l").unwrap()),
            ["abort01", "accept01", "acct02"]
        );
        assert_eq!(
            names(select(tests.clone(), "abort01 acct02", "02$", "l").unwrap()),
            ["acct02"]
        );
        assert_eq!(names(select(tests.clone(), "", "", "l").unwrap()).len(), 6);
        assert_eq!(
            select(tests.clone(), "nope abort01 zz", "", "l").unwrap_err(),
            "Not in l: nope zz"
        );
        assert_eq!(
            select(tests.clone(), "", "^xyz", "l").unwrap_err(),
            "No tests selected."
        );
        assert!(select(tests, "", "(", "l").is_err());
    }
}
