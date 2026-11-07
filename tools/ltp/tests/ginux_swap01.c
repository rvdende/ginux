// SPDX-License-Identifier: Apache-2.0
/*
 * ginux_swap01: oversubscribes a memory cgroup with swap on and checks that
 * every page comes back as it was written.
 *
 * A swap file on the test's device is turned on and the test moves into a
 * memory cgroup whose memory.max is a fraction of what its children map:
 * each child fills private anonymous memory with a pattern of its own and
 * rewrites and checks it round after round, so reclaim must page memory
 * out to swap and faults must read it back. Midway each child forks, and
 * the grandchild checks the pages it shares with its parent, swapped out
 * ones included, then overwrites half of them, which its parent must not
 * see. Then swap use must have shown in VmSwap, and all of it must be free
 * again once the children are gone. Next the test pages out a child's
 * private and shared anonymous memory with process_madvise(MADV_PAGEOUT):
 * VmSwap and smaps' Swap must show it, and the child must read it back
 * intact. Last, a child keeps pages out in swap while the test turns the
 * swap file off: swapoff must bring them back, intact.
 *
 * Ginux's own test (tools/ltp/tests), built against libltp with LTP's.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include "tst_test.h"
#include "tst_safe_stdio.h"
#include "tse_swap.h"
#include "lapi/mmap.h"
#include "lapi/syscalls.h"

#define MNTPOINT "mntpoint"
#define SWAP_FILE MNTPOINT "/swapfile"
#define SWAP_MB 192
#define MEM_LIMIT (32L << 20)
#define CHILDREN 3
#define CHILD_MAP (24L << 20)
#define ROUNDS 3

static long page_size;
static int swap_on;
/* Per child, the most it had in swap (VmSwap, KiB): shared with the test. */
static long *most_swapped_all;

static uint64_t pattern(uint64_t seed, long page, long word)
{
	uint64_t value = seed * 0x9e3779b97f4a7c15ULL + (uint64_t)page * 0x100000001b3ULL;

	return value ^ (uint64_t)word;
}

static void fill(uint64_t *map, long pages, uint64_t seed, long first, long step)
{
	long words = page_size / sizeof(uint64_t);

	for (long page = first; page < pages; page += step)
		for (long word = 0; word < words; word++)
			map[page * words + word] = pattern(seed, page, word);
}

/* The first page that does not hold seed's pattern, or -1. */
static long check(uint64_t *map, long pages, uint64_t seed, long first, long step)
{
	long words = page_size / sizeof(uint64_t);

	for (long page = first; page < pages; page += step)
		for (long word = 0; word < words; word++)
			if (map[page * words + word] != pattern(seed, page, word))
				return page;
	return -1;
}

static long vm_swap_kib(void)
{
	long swapped = 0;

	FILE_LINES_SCANF("/proc/self/status", "VmSwap: %ld", &swapped);
	return swapped;
}

static void child(int index)
{
	long pages = CHILD_MAP / page_size;
	uint64_t *map = SAFE_MMAP(NULL, CHILD_MAP, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	uint64_t seed = 1000 + index;
	long most_swapped = 0;
	long bad;

	fill(map, pages, seed, 0, 1);
	for (int round = 0; round < ROUNDS; round++) {
		/* Just after a fill, the most is out. */
		if (vm_swap_kib() > most_swapped)
			most_swapped = vm_swap_kib();
		bad = check(map, pages, seed, 0, 1);
		if (bad >= 0) {
			tst_res(TFAIL, "child %d round %d: page %ld changed",
				index, round, bad);
			exit(1);
		}
		if (round == 1) {
			pid_t grandchild = SAFE_FORK();

			if (!grandchild) {
				bad = check(map, pages, seed, 0, 1);
				if (bad >= 0) {
					tst_res(TFAIL, "child %d's fork: inherited page %ld differs",
						index, bad);
					exit(1);
				}
				fill(map, pages, seed + 7777, 0, 2);
				bad = check(map, pages, seed + 7777, 0, 2);
				if (bad < 0)
					bad = check(map, pages, seed, 1, 2);
				exit(bad >= 0);
			}
			int status;

			SAFE_WAITPID(grandchild, &status, 0);
			if (!WIFEXITED(status) || WEXITSTATUS(status)) {
				tst_res(TFAIL, "child %d's fork saw wrong pages", index);
				exit(1);
			}
			bad = check(map, pages, seed, 0, 1);
			if (bad >= 0) {
				tst_res(TFAIL, "child %d: its fork's write reached page %ld",
					index, bad);
				exit(1);
			}
		}
		seed += 100;
		fill(map, pages, seed, 0, 1);
	}
	bad = check(map, pages, seed, 0, 1);
	if (bad >= 0) {
		tst_res(TFAIL, "child %d: page %ld changed at the end", index, bad);
		exit(1);
	}
	tst_res(TINFO, "child %d: %ld KiB at most in swap (VmSwap)", index, most_swapped);
	most_swapped_all[index] = most_swapped;
	SAFE_MUNMAP(map, CHILD_MAP);
	exit(0);
}

static long swap_used_kib(void)
{
	return SAFE_READ_MEMINFO("SwapTotal:") - SAFE_READ_MEMINFO("SwapFree:");
}

static void oversubscribe(void)
{
	long before = swap_used_kib();
	long swapped = 0;
	int failed = 0;

	for (int index = 0; index < CHILDREN; index++)
		if (!SAFE_FORK())
			child(index);
	for (int index = 0; index < CHILDREN; index++) {
		int status;

		SAFE_WAIT(&status);
		if (!WIFEXITED(status) || WEXITSTATUS(status))
			failed = 1;
	}
	if (failed)
		tst_res(TFAIL, "a child's pages did not come back as written");
	else
		tst_res(TPASS, "%d children with %ld MiB each in %ld MiB: every page intact",
			CHILDREN, CHILD_MAP >> 20, MEM_LIMIT >> 20);
	for (int index = 0; index < CHILDREN; index++)
		swapped += most_swapped_all[index];
	if (swapped > 0)
		tst_res(TPASS, "the children had up to %ld KiB in swap (VmSwap)", swapped);
	else
		tst_res(TFAIL, "VmSwap stayed 0: nothing was swapped out");
	if (SAFE_CG_HAS(tst_cg, "memory.swap.current")) {
		long current;

		SAFE_CG_SCANF(tst_cg, "memory.swap.current", "%ld", &current);
		if (current == 0)
			tst_res(TPASS, "memory.swap.current is 0 again");
		else
			tst_res(TFAIL, "memory.swap.current is %ld after the children exited",
				current);
	}
	if (swap_used_kib() == before)
		tst_res(TPASS, "the children's swap is free again");
	else
		tst_res(TFAIL, "%ld KiB of swap still used after the children exited",
			swap_used_kib() - before);
}

/* The Swap: of the smaps entry of the mapping at `start`, in KiB. */
static long smaps_swap_kib(void *start)
{
	char line[256], first[32];
	long swapped = -1;
	int found = 0;
	FILE *smaps = SAFE_FOPEN("/proc/self/smaps", "r");

	snprintf(first, sizeof(first), "%lx-", (unsigned long)start);
	while (fgets(line, sizeof(line), smaps)) {
		if (strchr(line, '-') && strncmp(line, first, strlen(first)) == 0)
			found = 1;
		else if (found && sscanf(line, "Swap: %ld kB", &swapped) == 1)
			break;
	}
	SAFE_FCLOSE(smaps);
	return swapped;
}

#define PAGEOUT_MAP (1L << 20)

static void pageout_another_process(void)
{
	long pages = PAGEOUT_MAP / page_size;
	int ready[2], resume[2];
	char byte = 0;
	int status;

	/* No limit: only the advice pages anything out. */
	SAFE_CG_PRINT(tst_cg, "memory.max", "max");
	SAFE_PIPE(ready);
	SAFE_PIPE(resume);
	pid_t pid = SAFE_FORK();

	if (!pid) {
		uint64_t *private = SAFE_MMAP(NULL, PAGEOUT_MAP, PROT_READ | PROT_WRITE,
					      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		uint64_t *shared = SAFE_MMAP(NULL, PAGEOUT_MAP, PROT_READ | PROT_WRITE,
					     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		void *addresses[2] = {private, shared};
		long bad;
		int failed = 0;

		fill(private, pages, 31, 0, 1);
		fill(shared, pages, 32, 0, 1);
		SAFE_WRITE(SAFE_WRITE_ALL, ready[1], addresses, sizeof(addresses));
		SAFE_READ(1, resume[0], &byte, 1);
		long vm_swap = vm_swap_kib();
		long shared_swap = smaps_swap_kib(shared);

		if (vm_swap >= PAGEOUT_MAP / 1024)
			tst_res(TPASS, "private pages paged out: VmSwap %ld KiB", vm_swap);
		else
			tst_res(TFAIL, "private pages paged out: VmSwap %ld KiB", vm_swap);
		if (shared_swap >= PAGEOUT_MAP / 1024)
			tst_res(TPASS, "shared pages paged out: smaps Swap %ld KiB", shared_swap);
		else
			tst_res(TFAIL, "shared pages paged out: smaps Swap %ld KiB", shared_swap);
		bad = check(private, pages, 31, 0, 1);
		if (bad >= 0) {
			tst_res(TFAIL, "private page %ld changed after MADV_PAGEOUT", bad);
			failed = 1;
		}
		bad = check(shared, pages, 32, 0, 1);
		if (bad >= 0) {
			tst_res(TFAIL, "shared page %ld changed after MADV_PAGEOUT", bad);
			failed = 1;
		}
		if (vm_swap_kib() != 0 || smaps_swap_kib(shared) != 0) {
			tst_res(TFAIL, "pages read back still counted in swap");
			failed = 1;
		}
		exit(failed);
	}
	void *addresses[2];

	SAFE_READ(1, ready[0], addresses, sizeof(addresses));
	int pidfd = tst_syscall(__NR_pidfd_open, pid, 0);

	if (pidfd < 0)
		tst_brk(TBROK | TERRNO, "pidfd_open");
	struct iovec vectors[2] = {
		{.iov_base = addresses[0], .iov_len = PAGEOUT_MAP},
		{.iov_base = addresses[1], .iov_len = PAGEOUT_MAP},
	};
	TEST(tst_syscall(__NR_process_madvise, pidfd, vectors, 2, MADV_PAGEOUT, 0));
	if (TST_RET == 2 * PAGEOUT_MAP)
		tst_res(TPASS, "process_madvise(MADV_PAGEOUT) advised %ld bytes", TST_RET);
	else
		tst_res(TFAIL | TTERRNO, "process_madvise(MADV_PAGEOUT) returned %ld", TST_RET);
	SAFE_CLOSE(pidfd);
	SAFE_WRITE(SAFE_WRITE_ALL, resume[1], &byte, 1);
	SAFE_WAITPID(pid, &status, 0);
	if (WIFEXITED(status) && !WEXITSTATUS(status))
		tst_res(TPASS, "the pages paged out came back intact");
	else
		tst_res(TFAIL, "the paged-out child failed");
	SAFE_CG_PRINTF(tst_cg, "memory.max", "%ld", MEM_LIMIT);
}

static void swapoff_with_pages_out(void)
{
	long pages = 2 * CHILD_MAP / page_size;
	int ready[2], resume[2];
	char byte = 0;
	int status;

	SAFE_PIPE(ready);
	SAFE_PIPE(resume);
	pid_t pid = SAFE_FORK();

	if (!pid) {
		uint64_t *map = SAFE_MMAP(NULL, 2 * CHILD_MAP, PROT_READ | PROT_WRITE,
					  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		/* Twice what the cgroup may hold: much of it goes out. */
		fill(map, pages, 4242, 0, 1);
		long swapped = vm_swap_kib();

		SAFE_WRITE(SAFE_WRITE_ALL, ready[1], &swapped, sizeof(swapped));
		SAFE_READ(1, resume[0], &byte, 1);
		long bad = check(map, pages, 4242, 0, 1);

		if (bad >= 0)
			tst_res(TFAIL, "page %ld changed across swapoff", bad);
		exit(bad >= 0);
	}
	long swapped;

	SAFE_READ(1, ready[0], &swapped, sizeof(swapped));
	tst_res(TINFO, "%ld KiB of the child's pages in swap before swapoff", swapped);
	/* Room for the pages to come back to. */
	SAFE_CG_PRINT(tst_cg, "memory.max", "max");
	TEST(tst_syscall(__NR_swapoff, SWAP_FILE));
	if (TST_RET == 0) {
		swap_on = 0;
		tst_res(TPASS, "swapoff with %ld KiB out in swap", swapped);
	} else {
		tst_res(TFAIL | TTERRNO, "swapoff with %ld KiB out in swap", swapped);
	}
	SAFE_WRITE(SAFE_WRITE_ALL, resume[1], &byte, 1);
	SAFE_WAITPID(pid, &status, 0);
	if (WIFEXITED(status) && !WEXITSTATUS(status))
		tst_res(TPASS, "the pages swapoff brought back are intact");
	else
		tst_res(TFAIL, "the child's pages did not survive swapoff");
	if (swapped == 0)
		tst_res(TFAIL, "nothing was in swap at swapoff");
}

static void run(void)
{
	if (!swap_on) {
		TST_EXP_PASS_SILENT(tst_syscall(__NR_swapon, SWAP_FILE, 0));
		swap_on = TST_PASS;
	}
	SAFE_CG_PRINTF(tst_cg, "memory.max", "%ld", MEM_LIMIT);
	oversubscribe();
	pageout_another_process();
	swapoff_with_pages_out();
}

static void setup(void)
{
	page_size = getpagesize();
	most_swapped_all = SAFE_MMAP(NULL, page_size, PROT_READ | PROT_WRITE,
				     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	is_swap_supported(SWAP_FILE);
	MAKE_SWAPFILE_SIZE(SWAP_FILE, SWAP_MB);
	SAFE_CG_PRINTF(tst_cg, "cgroup.procs", "%d", getpid());
	if (SAFE_CG_HAS(tst_cg, "memory.swap.max"))
		SAFE_CG_PRINT(tst_cg, "memory.swap.max", "max");
}

static void cleanup(void)
{
	if (swap_on && tst_syscall(__NR_swapoff, SWAP_FILE))
		tst_res(TWARN | TERRNO, "swapoff");
}

static struct tst_test test = {
	.mntpoint = MNTPOINT,
	.mount_device = 1,
	.filesystems = (struct tst_fs []) {
		{.type = "ext4"},
		{}
	},
	.dev_min_size = SWAP_MB + 64,
	.needs_root = 1,
	.forks_child = 1,
	.needs_cgroup_ctrls = (const char *const []){ "memory", NULL },
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.timeout = 300,
};
