/*
 * Diagnostic LTP build variant: tools/ltp/build.sh --variant no-oom-protection
 *
 * LTP's library lowers its own /proc/PID/oom_score_adj to -1000 before every
 * new-API test and checks that the value stuck. Ginux accepts the write but
 * keeps no value, so every new-API test stops before running with
 * "TBROK: oom_score_adj = 0, but expect -1000." This variant replaces the two
 * library functions with no-ops (linked first, with -z muldefs, so these
 * definitions win over libltp.a's) to show what fails behind that one bug.
 * LTP's sources are not changed; the default build does not use this.
 */
#include <sys/types.h>

void tst_enable_oom_protection(pid_t pid);
void tst_disable_oom_protection(pid_t pid);

void tst_enable_oom_protection(pid_t pid)
{
	(void)pid;
}

void tst_disable_oom_protection(pid_t pid)
{
	(void)pid;
}
