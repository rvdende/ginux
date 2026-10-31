/*
 * ltp-runner: runs LTP tests one at a time inside a Ginux domain and
 * reports each on the console for tests/qemu/ltp.sh.
 *
 *   ltp-runner RUNLIST FIRST
 *
 * RUNLIST has one test per line: INDEX TAB TAG TAB BUDGET TAB COMMAND.
 * Tests with INDEX >= FIRST run in order. Each runs as `sh -c "exec
 * COMMAND"` in its own process group with stdin on /dev/null and its
 * output on the console, bracketed by
 *
 *   @@LTP BEGIN INDEX TAG
 *   @@LTP END INDEX TAG STATUS MILLISECONDS LEFTOVER
 *
 * where STATUS is exit=N, signal=N, timeout, or lost:wait=R,errno=E when
 * waitpid fails. The per-test time budget is enforced here, in the guest:
 * when BUDGET seconds pass (SIGALRM), the test's process group is killed and
 * STATUS is timeout. Processes a test leaves behind (its forked children run
 * in their own process groups) are then killed through /proc and counted in
 * LEFTOVER, so they cannot disturb the next test.
 *
 * This replaces busybox timeout, whose vfork-and-daemonize watcher takes the
 * whole domain down on Ginux today. On Ginux the alarm does not fire while
 * another process spins on the CPU, so the host (tests/ltp/driver.py) keeps
 * its own watchdog as well.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t alarm_fired;

static void on_alarm(int sig)
{
	(void)sig;
	alarm_fired = 1;
}

/* Signals a test may send to its parent; handled (not ignored) so exec in
 * the child resets them to their defaults. */
static void on_ignored(int sig)
{
	(void)sig;
}

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void say(const char *fmt, ...)
{
	char line[512];
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (len < 0)
		return;
	if ((size_t)len >= sizeof(line))
		len = sizeof(line) - 1;
	/* One write per marker keeps it from interleaving with test output. */
	if (write(STDOUT_FILENO, line, len) < 0)
		return;
}

static long elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000L +
	       (now.tv_nsec - start->tv_nsec) / 1000000L;
}

/* Kills every process in the domain except this one, its parent and init;
 * returns how many there were. */
static int kill_leftovers(void)
{
	DIR *proc = opendir("/proc");
	struct dirent *entry;
	pid_t self = getpid(), parent = getppid();
	int count = 0;

	if (!proc)
		return -1;
	while ((entry = readdir(proc))) {
		char *end;
		long pid = strtol(entry->d_name, &end, 10);

		if (*end || pid <= 1 || pid == self || pid == parent)
			continue;
		if (kill((pid_t)pid, SIGKILL) == 0)
			count++;
	}
	closedir(proc);
	return count;
}

static void reap_all(void)
{
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

static int remove_entry(const char *path, const struct stat *st, int flag,
			struct FTW *ftw)
{
	(void)st;
	(void)flag;
	if (ftw->level > 0)
		remove(path);
	return 0;
}

/* Empties TMPDIR, where a killed test leaves its LTP_* directory. */
static void clean_tmpdir(const char *tmpdir)
{
	nftw(tmpdir, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
}

static void run_child(const char *command, const char *tmpdir)
{
	static const int reset[] = { SIGALRM, SIGHUP, SIGINT, SIGQUIT, SIGTERM,
				     SIGUSR1, SIGUSR2, SIGPIPE, SIGTTIN, SIGTTOU,
				     SIGTSTP, SIGCHLD };
	sigset_t none;
	char *shell_command;
	size_t i;
	int null_fd;

	for (i = 0; i < sizeof(reset) / sizeof(reset[0]); i++)
		signal(reset[i], SIG_DFL);
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	setpgid(0, 0);
	null_fd = open("/dev/null", O_RDONLY);
	if (null_fd >= 0) {
		dup2(null_fd, STDIN_FILENO);
		if (null_fd != STDIN_FILENO)
			close(null_fd);
	}
	if (chdir(tmpdir) != 0 && chdir("/") != 0)
		_exit(126);
	if (asprintf(&shell_command, "exec %s", command) < 0)
		_exit(126);
	execl("/bin/sh", "sh", "-c", shell_command, (char *)NULL);
	_exit(127);
}

static void run_test(long index, const char *tag, unsigned budget,
		     const char *command, const char *tmpdir)
{
	struct timespec start;
	char status_text[48];
	int status = 0, timed_out = 0, lost = 0, lost_errno = 0, leftover;
	pid_t pid, lost_result = 0;

	say("\n@@LTP BEGIN %ld %s\n", index, tag);
	clock_gettime(CLOCK_MONOTONIC, &start);
	pid = fork();
	if (pid < 0) {
		say("\n@@LTP END %ld %s fork-errno=%d %ld 0\n", index, tag,
		    errno, elapsed_ms(&start));
		return;
	}
	if (pid == 0)
		run_child(command, tmpdir);
	setpgid(pid, pid);

	alarm_fired = 0;
	alarm(budget);
	for (;;) {
		pid_t done = waitpid(pid, &status, 0);
		int wait_errno = errno;

		if (done == pid)
			break;
		if (alarm_fired && !timed_out) {
			timed_out = 1;
			kill(-pid, SIGKILL);
			kill(pid, SIGKILL);
			continue;
		}
		if (done < 0 && wait_errno == EINTR)
			continue;
		/* waitpid failed some other way (a kernel bug): stop waiting. */
		lost = 1;
		lost_result = done;
		lost_errno = done < 0 ? wait_errno : 0;
		break;
	}
	alarm(0);

	if (timed_out)
		snprintf(status_text, sizeof(status_text), "timeout");
	else if (lost)
		snprintf(status_text, sizeof(status_text), "lost:wait=%d,errno=%d",
			 (int)lost_result, lost_errno);
	else if (WIFEXITED(status))
		snprintf(status_text, sizeof(status_text), "exit=%d",
			 WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		snprintf(status_text, sizeof(status_text), "signal=%d",
			 WTERMSIG(status));
	else
		snprintf(status_text, sizeof(status_text), "status=%d", status);

	long duration = elapsed_ms(&start);

	reap_all();
	leftover = kill_leftovers();
	reap_all();
	clean_tmpdir(tmpdir);
	say("\n@@LTP END %ld %s %s %ld %d\n", index, tag, status_text, duration,
	    leftover);
}

int main(int argc, char **argv)
{
	static const int handled[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1,
				       SIGUSR2, SIGPIPE, SIGTTIN, SIGTTOU, SIGTSTP };
	struct sigaction action;
	const char *tmpdir;
	char *line = NULL;
	size_t capacity = 0;
	long first, count = 0;
	size_t i;
	FILE *list;

	if (argc != 3) {
		fprintf(stderr, "usage: %s RUNLIST FIRST\n", argv[0]);
		return 2;
	}
	first = strtol(argv[2], NULL, 10);
	list = fopen(argv[1], "r");
	if (!list) {
		perror(argv[1]);
		return 1;
	}
	tmpdir = getenv("TMPDIR");
	if (!tmpdir || !*tmpdir)
		tmpdir = "/tmp";
	mkdir(tmpdir, 0777);

	memset(&action, 0, sizeof(action));
	action.sa_handler = on_alarm;
	sigemptyset(&action.sa_mask);
	/* No SA_RESTART: the alarm must interrupt waitpid. */
	sigaction(SIGALRM, &action, NULL);
	action.sa_handler = on_ignored;
	for (i = 0; i < sizeof(handled) / sizeof(handled[0]); i++)
		sigaction(handled[i], &action, NULL);

	while (getline(&line, &capacity, list) > 0)
		count++;
	rewind(list);
	say("\n@@LTP READY %ld %ld\n", count, first);

	while (getline(&line, &capacity, list) > 0) {
		char *fields[4];
		char *cursor = line;
		int n;

		line[strcspn(line, "\n")] = '\0';
		for (n = 0; n < 4 && cursor; n++)
			fields[n] = strsep(&cursor, "\t");
		if (n < 4 || !fields[3] || !*fields[3])
			continue;
		long index = strtol(fields[0], NULL, 10);
		if (index < first)
			continue;
		run_test(index, fields[1], (unsigned)strtoul(fields[2], NULL, 10),
			 fields[3], tmpdir);
	}
	say("\n@@LTP DONE\n");
	return 0;
}
