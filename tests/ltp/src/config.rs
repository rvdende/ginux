//! The harness's settings, from the environment (libtest owns the command
//! line; `tests/qemu/ltp.sh` translates its options into these variables).

use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// What to run and how.
#[derive(Clone, Debug)]
pub struct Config {
    /// The repository root.
    pub repo: PathBuf,
    /// The run list (`LTP_LIST`, default `tests/ltp/syscalls.list`).
    pub list: PathBuf,
    /// Space-separated test names to run (`LTP_TESTS`; all when empty).
    pub tests: String,
    /// A regular expression selecting test names (`LTP_FILTER`).
    pub filter: String,
    /// The budget of a test whose list entry sets none (`LTP_BUDGET`).
    pub default_budget: u32,
    /// Seconds past a budget before the host declares the guest wedged
    /// (`LTP_GRACE`).
    pub grace: u64,
    /// Seconds the runner may take between tests (`LTP_BETWEEN_TESTS`).
    pub between_tests: u64,
    /// Seconds the domain may take to unpack LTP and start the runner
    /// (`LTP_SETUP_TIMEOUT`).
    pub setup_timeout: u64,
    /// Boots after which the run stops (`LTP_MAX_BOOTS`).
    pub max_boots: u32,
    /// QEMU's memory (`GINUX_MEMORY`).
    pub memory: String,
    /// The domain's memory (`LTP_DOMAIN_MEMORY_MIB`).
    pub domain_memory_mib: u32,
    /// The domain's image (`LTP_IMAGE`).
    pub image: String,
    /// The LTP build to use, `build/ltp-VARIANT`, which also suffixes the
    /// outputs (`LTP_VARIANT`; the default build when empty).
    pub variant: String,
    /// The ESP directory to boot (`GINUX_ESP_DIR`, default `build/esp`).
    pub esp_dir: PathBuf,
    /// Report every failure, ignoring the baseline (`LTP_STRICT=1`).
    pub strict: bool,
    /// Rewrite the baseline from this run's results
    /// (`LTP_UPDATE_BASELINE=1`).
    pub update_baseline: bool,
    /// The baseline file (`LTP_BASELINE`, default `tests/ltp/baseline.txt`).
    pub baseline: PathBuf,
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn number<T: FromStr>(name: &str, default: T) -> Result<T, String> {
    match var(name) {
        Some(value) => value
            .trim()
            .parse()
            .map_err(|_| format!("{name}={value} is not a number")),
        None => Ok(default),
    }
}

fn switch(name: &str) -> Result<bool, String> {
    match var(name).as_deref() {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(format!("{name}={other}: expected 0 or 1")),
    }
}

impl Config {
    /// Reads the settings. Relative paths are taken from the repository
    /// root; `strict` and `update_baseline` are the command-line switches.
    pub fn from_env(repo: PathBuf, strict: bool, update_baseline: bool) -> Result<Self, String> {
        let path =
            |name: &str, default: &str| repo.join(var(name).unwrap_or_else(|| default.to_string()));
        Ok(Config {
            list: path("LTP_LIST", "tests/ltp/syscalls.list"),
            tests: var("LTP_TESTS").unwrap_or_default(),
            filter: var("LTP_FILTER").unwrap_or_default(),
            default_budget: number("LTP_BUDGET", 60)?,
            grace: number("LTP_GRACE", 30)?,
            between_tests: number("LTP_BETWEEN_TESTS", 60)?,
            setup_timeout: number("LTP_SETUP_TIMEOUT", 600)?,
            max_boots: number("LTP_MAX_BOOTS", 400)?,
            memory: var("GINUX_MEMORY").unwrap_or_else(|| "6G".to_string()),
            domain_memory_mib: number("LTP_DOMAIN_MEMORY_MIB", 4096)?,
            image: var("LTP_IMAGE").unwrap_or_else(|| "alpine:3.22".to_string()),
            variant: var("LTP_VARIANT").unwrap_or_default(),
            esp_dir: path("GINUX_ESP_DIR", "build/esp"),
            strict: strict || switch("LTP_STRICT")?,
            update_baseline: update_baseline || switch("LTP_UPDATE_BASELINE")?,
            baseline: path("LTP_BASELINE", "tests/ltp/baseline.txt"),
            repo,
        })
    }

    /// `-VARIANT`, or nothing for the default build.
    pub fn suffix(&self) -> String {
        if self.variant.is_empty() {
            String::new()
        } else {
            format!("-{}", self.variant)
        }
    }

    /// The LTP build: `build/ltp` or `build/ltp-VARIANT`.
    pub fn ltp_dir(&self) -> PathBuf {
        self.repo.join(format!("build/ltp{}", self.suffix()))
    }

    /// The run's working directory: logs, the volume, the served files.
    pub fn work(&self) -> PathBuf {
        self.repo.join(format!("target/ltp{}", self.suffix()))
    }

    /// The results file.
    pub fn results(&self) -> PathBuf {
        self.repo
            .join(format!("target/ltp-results{}.txt", self.suffix()))
    }

    /// The whole serial console of every boot.
    pub fn serial_log(&self) -> PathBuf {
        self.repo
            .join(format!("target/ltp-serial{}.log", self.suffix()))
    }

    /// Each test's console output.
    pub fn logs(&self) -> PathBuf {
        self.work().join("logs")
    }

    /// The Ginux volume, fresh for each run.
    pub fn volume(&self) -> PathBuf {
        self.work().join("volume.raw")
    }

    /// Where run.sh records QEMU's process id.
    pub fn pid_file(&self) -> PathBuf {
        self.work().join("qemu.pid")
    }

    /// `path` relative to the repository, if it is inside it.
    pub fn display(&self, path: &Path) -> String {
        path.strip_prefix(&self.repo)
            .unwrap_or(path)
            .display()
            .to_string()
    }

    /// `path` relative to the repository, with `..` to leave it (as
    /// Python's `os.path.relpath`): how the results file names the list.
    pub fn relative(&self, path: &Path) -> String {
        relative_path(path, &self.repo).display().to_string()
    }
}

/// `path` relative to the directory `base`; both absolute.
pub fn relative_path(path: &Path, base: &Path) -> PathBuf {
    let path: Vec<_> = path.components().collect();
    let base: Vec<_> = base.components().collect();
    let common = path.iter().zip(&base).take_while(|(a, b)| a == b).count();
    let mut relative: PathBuf = base[common..].iter().map(|_| "..").collect();
    relative.extend(&path[common..]);
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    relative
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_like_relpath() {
        let repo = Path::new("/home/u/ginux");
        assert_eq!(
            relative_path(Path::new("/home/u/ginux/tests/ltp/x.list"), repo),
            Path::new("tests/ltp/x.list")
        );
        assert_eq!(
            relative_path(Path::new("/tmp/a/b.list"), repo),
            Path::new("../../../tmp/a/b.list")
        );
        assert_eq!(
            relative_path(Path::new("/home/u/other.list"), repo),
            Path::new("../other.list")
        );
        assert_eq!(relative_path(repo, repo), Path::new("."));
    }
}
