// SPDX-License-Identifier: Apache-2.0
/*
 * ginux_stack01: the main stack grows down to RLIMIT_STACK, and no further.
 *
 * A child recurses with large frames, noting how deep its stack went in
 * memory shared with the test, until the stack can grow no more and the
 * fault is SIGSEGV, which a handler on an alternate signal stack takes.
 * With the default limit (8 MiB) the stack must reach well past what
 * the heap would allow below a stack placed above it, and stop before the
 * limit; with RLIMIT_STACK lowered to 2 MiB first, the stack must stop
 * there. /proc/self/maps must name the stack, near the top of the address
 * space.
 *
 * Ginux's own test (tools/ltp/tests), built against libltp with LTP's.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include "tst_test.h"
#include "tst_safe_stdio.h"

#define FRAME (64 * 1024)

static volatile unsigned long *deepest;
static unsigned long stack_top;

static void on_segv(int sig)
{
	(void)sig;
	_exit(0);
}

static void LTP_ATTRIBUTE_NOINLINE descend(void)
{
	volatile char frame[FRAME];
	unsigned long here = (unsigned long)frame;

	frame[0] = frame[FRAME - 1] = 1;
	if (stack_top - here > *deepest)
		*deepest = stack_top - here;
	descend();
	frame[1] = 0;
}

/* How deep a child's stack grew before SIGSEGV, with RLIMIT_STACK at `limit` (0: as it is). */
static unsigned long depth_with_limit(rlim_t limit)
{
	int status;

	*deepest = 0;
	pid_t pid = SAFE_FORK();

	if (!pid) {
		static char alternate[64 * 1024];
		stack_t stack = {.ss_sp = alternate, .ss_size = sizeof(alternate)};
		struct sigaction action = {.sa_handler = on_segv, .sa_flags = SA_ONSTACK};
		int marker;

		if (limit) {
			struct rlimit rlimit;

			SAFE_GETRLIMIT(RLIMIT_STACK, &rlimit);
			rlimit.rlim_cur = limit;
			SAFE_SETRLIMIT(RLIMIT_STACK, &rlimit);
		}
		if (sigaltstack(&stack, NULL))
			tst_brk(TBROK | TERRNO, "sigaltstack");
		SAFE_SIGACTION(SIGSEGV, &action, NULL);
		stack_top = (unsigned long)&marker;
		descend();
		exit(1);
	}
	SAFE_WAITPID(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		tst_res(TFAIL, "the child did not end in SIGSEGV on its alternate stack");
	return *deepest;
}

static void run(void)
{
	char line[256];
	unsigned long start, end;
	int found = 0;
	FILE *maps = SAFE_FOPEN("/proc/self/maps", "r");

	while (fgets(line, sizeof(line), maps)) {
		if (strstr(line, "[stack]") && sscanf(line, "%lx-%lx", &start, &end) == 2) {
			found = 1;
			break;
		}
	}
	SAFE_FCLOSE(maps);
	if (found && end > (1UL << 46))
		tst_res(TPASS, "[stack] at %lx-%lx, near the top", start, end);
	else
		tst_res(TFAIL, "[stack] not near the top of the address space");

	unsigned long depth = depth_with_limit(0);

	if (depth > (6UL << 20) && depth < (8UL << 20))
		tst_res(TPASS, "default RLIMIT_STACK: grew to %lu KiB, stopped before 8 MiB",
			depth >> 10);
	else
		tst_res(TFAIL, "default RLIMIT_STACK: grew to %lu KiB", depth >> 10);

	depth = depth_with_limit(2UL << 20);
	if (depth > (1UL << 20) && depth < (2UL << 20))
		tst_res(TPASS, "RLIMIT_STACK 2 MiB: grew to %lu KiB, stopped before 2 MiB",
			depth >> 10);
	else
		tst_res(TFAIL, "RLIMIT_STACK 2 MiB: grew to %lu KiB", depth >> 10);
}

static void setup(void)
{
	struct rlimit rlimit;

	SAFE_GETRLIMIT(RLIMIT_STACK, &rlimit);
	if (rlimit.rlim_cur != 8UL << 20)
		tst_res(TINFO, "RLIMIT_STACK is %lu, not 8 MiB", (unsigned long)rlimit.rlim_cur);
	deepest = SAFE_MMAP(NULL, getpagesize(), PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.forks_child = 1,
};
