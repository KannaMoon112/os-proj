/*
 * malloc_test.c — Target process for VMA visualizer demo
 *
 * Scenarios demonstrated:
 *   1. Heap growth via brk  (small allocs < 128 KB)
 *   2. Heap growth via mmap (large allocs >= 128 KB)
 *   3. Memory leak: repeated malloc without free
 *   4. Fork: parent+child memory map clone
 *   5. Anonymous mmap directly
 *
 * Build:
 *   gcc -o malloc_full_test malloc_full_test.c
 *
 * Run (as root, after insmod vma_tracker.ko):
 *   ./malloc_test [scenario]
 *   scenario: heap | leak | fork | mmap | all (default: all)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define SMALL   (32  * 1024)        /* 32 KB  -> brk */
#define LARGE   (256 * 1024)        /* 256 KB -> mmap */
#define DELAY_US 600000             /* 0.6 s between ops */

static void wait_us(int us) { usleep(us); }

/* ── Scenario 1: heap grow/shrink ───────────────────────────── */
static void scenario_heap(void) {
    printf("\n[heap] Starting heap grow/shrink demo\n");
    void *p[8] = {0};

    for (int i = 0; i < 8; i++) {
        p[i] = malloc(SMALL * (i + 1));
        printf("[heap] alloc %d KB at %p\n",
               (int)((SMALL * (i+1)) / 1024), p[i]);
        wait_us(DELAY_US);
    }
    printf("[heap] Peak allocated. Now freeing...\n");
    for (int i = 7; i >= 0; i--) {
        free(p[i]);
        printf("[heap] free slot %d\n", i);
        wait_us(DELAY_US);
    }
}

/* ── Scenario 2: memory leak (heap only grows) ────────────── */
static void scenario_leak(void) {
    printf("\n[leak] Simulating memory leak (no free)\n");
    for (int i = 0; i < 12; i++) {
        void *p = malloc(SMALL);
        memset(p, 0xAB, SMALL);   /* touch to force page allocation */
        printf("[leak] alloc %d KB at %p (not freed)\n",
               SMALL / 1024, p);
        wait_us(DELAY_US);
    }
    printf("[leak] Process exiting — all leaked memory reclaimed by OS\n");
    wait_us(DELAY_US * 3);
}

/* ── Scenario 3: large mmap allocations ─────────────────────── */
static void scenario_mmap(void) {
    printf("\n[mmap] Large allocations via mmap\n");
    void *ptrs[4] = {0};

    for (int i = 0; i < 4; i++) {
        size_t sz = LARGE * (1 << i);
        ptrs[i] = malloc(sz);
        printf("[mmap] alloc %.1f MB at %p (via mmap)\n",
               (double)sz / (1024*1024), ptrs[i]);
        wait_us(DELAY_US);
    }
    for (int i = 0; i < 4; i++) {
        free(ptrs[i]);
        printf("[mmap] free slot %d\n", i);
        wait_us(DELAY_US);
    }
}

/* ── Scenario 4: direct anonymous mmap ─────────────────────── */
static void scenario_anon_mmap(void) {
    printf("\n[anon_mmap] Direct anonymous mmap demo\n");
    void *p = mmap(NULL, 2 * 1024 * 1024,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return; }
    printf("[anon_mmap] mapped 2 MB at %p\n", p);
    memset(p, 0x42, 4096);
    wait_us(DELAY_US * 3);
    munmap(p, 2 * 1024 * 1024);
    printf("[anon_mmap] unmapped\n");
    wait_us(DELAY_US);
}

/* ── Scenario 5: fork ───────────────────────────────────────── */
static void scenario_fork(void) {
    printf("\n[fork] Fork demo\n");

    /* Allocate some memory first */
    void *p = malloc(LARGE);
    printf("[fork] parent allocated %d KB before fork\n", LARGE/1024);
    wait_us(DELAY_US);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return; }

    if (pid == 0) {
        /* child */
        printf("[fork] child PID=%d — will allocate independently\n",
               getpid());
        wait_us(DELAY_US);
        void *cp = malloc(SMALL * 3);
        printf("[fork] child allocated %d KB at %p (CoW diverge)\n",
               (SMALL * 3)/1024, cp);
        wait_us(DELAY_US * 4);
        free(cp);
        free(p);
        printf("[fork] child exiting\n");
        exit(0);
    } else {
        printf("[fork] parent PID=%d, child=%d\n", getpid(), pid);
        wait_us(DELAY_US * 2);
        void *pp = malloc(SMALL * 5);
        printf("[fork] parent allocated extra %d KB\n", (SMALL*5)/1024);
        wait_us(DELAY_US * 4);
        free(pp);
        free(p);
        waitpid(pid, NULL, 0);
        printf("[fork] child joined\n");
    }
}

/* ── main ───────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    srand((unsigned)time(NULL));

    printf("=== VMA Tracker Demo ===\n");
    printf("PID: %d\n", getpid());
    printf("Watch: /sys/kernel/debug/vma_tracker/data\n");
    printf("Or open: http://localhost:8000\n\n");

    const char *mode = (argc > 1) ? argv[1] : "all";

    if (strcmp(mode, "heap") == 0)      { scenario_heap(); }
    else if (strcmp(mode, "leak") == 0) { scenario_leak(); }
    else if (strcmp(mode, "mmap") == 0) { scenario_mmap(); }
    else if (strcmp(mode, "anon") == 0) { scenario_anon_mmap(); }
    else if (strcmp(mode, "fork") == 0) { scenario_fork(); }
    else {
        /* all scenarios sequentially */
        scenario_heap();
        scenario_mmap();
        scenario_anon_mmap();
        scenario_fork();
        scenario_leak();
    }

    printf("\n=== Demo complete ===\n");
    return 0;
}