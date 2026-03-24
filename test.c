#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#define PAGE_SIZE 4096

int main() {
    printf("Test Application Started. PID: %d\n", getpid());
    sleep(2); // 给加载内核模块留出时间

    // --- 第一步：触发 mmap ---
    printf("\n[1] Attempting mmap (Anonymous Mapping)...\n");
    
    // 分配 4 个页面的匿名内存，权限为 R/W
    void *addr = mmap(NULL, 4 * PAGE_SIZE, PROT_READ | PROT_WRITE, 
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (addr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }
    printf("Successfully mapped 16KB at address: %p\n", addr);
    
    // 写入数据以确保物理内存分配（触发 Page Fault）
    strcpy((char*)addr, "Hello from Parent!");
    sleep(3); 

    // --- 第二步：触发 fork (Option A) ---
    printf("\n[2] Attempting fork (Process Cloning)...\n");
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
    } else if (pid == 0) {
        // 子进程逻辑
        printf("I am Child Process (PID: %d). My parent is %d\n", getpid(), getppid());
        printf("Child sees data at %p: %s\n", addr, (char*)addr);
        
        // 修改数据触发 Copy-on-Write (COW)
        strcpy((char*)addr, "Modified by Child!");
        printf("Child modified data. Sleeping before exit...\n");
        sleep(5);
        exit(0);
    } else {
        // 父进程逻辑
        printf("I am Parent Process (PID: %d). Created child: %d\n", getpid(), pid);
        wait(NULL); // 等待子进程结束
        printf("Parent exiting.\n");
    }

    // 释放内存
    munmap(addr, 4 * PAGE_SIZE);
    return 0;
}