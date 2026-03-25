#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define MAX_PTRS 10
#define SMALL_MEM (10 * 1024)       // 10KB，通常触发 brk [cite: 121]
#define LARGE_MEM (10 * 1024 * 1024)      // 256KB，通常触发 mmap [cite: 123]

int main() {
    void *ptrs[MAX_PTRS] = {NULL};
    srand(time(NULL));

    printf("Malloc Test Started. PID: %d\n", getpid());
    printf("Check dmesg for VMA events...\n");

    for (int i = 0; i < 20; i++) {
        int idx = rand() % MAX_PTRS;

        if (i == 10) { // 在第 10 次循环时 fork
            printf("--- FORKING NOW ---\n");
            pid_t pid = fork();
            if (pid == 0) {
                printf("I am child, PID: %d\n", getpid());
            } else {
                printf("I am parent, Child PID: %d\n", pid);
            }
        }
        
        if (ptrs[idx] == NULL) {
            // 随机分配大内存或小内存以观察不同系统调用 
            size_t size = (rand() % 2 == 0) ? SMALL_MEM : LARGE_MEM;
            ptrs[idx] = malloc(size);
            printf("[%d] Allocated %zu bytes at %p\n", i, size, ptrs[idx]);
        } else {
            // 释放内存以观察 munmap 或 brk 缩小 
            printf("[%d] Freeing memory at %p\n", i, ptrs[idx]);
            free(ptrs[idx]);
            ptrs[idx] = NULL;
        }
        
        usleep(500000); // 停顿 0.5 秒，方便观察
    }

    return 0;
}