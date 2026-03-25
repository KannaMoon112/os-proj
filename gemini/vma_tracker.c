#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kfifo.h>
#include <linux/sched.h>

#define FIFO_SIZE 8192
static DECLARE_KFIFO(my_vma_fifo, char, FIFO_SIZE);
static struct dentry *my_vma_dir, *my_vma_file;
static DEFINE_SPINLOCK(my_vma_fifo_lock);

// 提取权限字符串
static void get_perms_str(unsigned long flags, char *perms) {
    perms[0] = (flags & VM_READ) ? 'r' : '-';
    perms[1] = (flags & VM_WRITE) ? 'w' : '-';
    perms[2] = (flags & VM_EXEC) ? 'x' : '-';
    perms[3] = '\0';
}

// 统一数据推送格式
static void push_vma_event(const char *op, unsigned long start, unsigned long end, 
                          const char *perms, const char *name) {
    char buf[256];
    int len;

    // 格式：EVENT_TYPE | PID | START_ADDR | END_ADDR | PERMS | FILE_NAME
    len = snprintf(buf, sizeof(buf), "%-6s | %-6d | 0x%012lx | 0x%012lx | %-5s | %s\n",
                   op, current->pid, start, end, perms, name);

    spin_lock(&my_vma_fifo_lock);
    if (!kfifo_is_full(&my_vma_fifo)) {
        kfifo_in(&my_vma_fifo, buf, len);
    }
    spin_unlock(&my_vma_fifo_lock);
}

/* --- 原有 Requirement 1 逻辑 --- */

static int handler_mmap_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    unsigned long addr = regs_return_value(regs);
    struct vm_area_struct *vma;
    char perms[4];
    const char *fname = "anon";

    if (strcmp(current->comm, "malloc_test") == 0 && addr < TASK_SIZE) {
        vma = find_vma(current->mm, addr);
        if (vma) {
            get_perms_str(vma->vm_flags, perms);
            if (vma->vm_file) fname = (char *)vma->vm_file->f_path.dentry->d_name.name;
            else if (vma->vm_flags & VM_STACK) fname = "[stack]";
            push_vma_event("MMAP", vma->vm_start, vma->vm_end, perms, fname);
        }
    }
    return 0;
}

static int handler_brk_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    if (strcmp(current->comm, "malloc_test") == 0) {
        push_vma_event("BRK", current->mm->start_brk, current->mm->brk, "rw-", "[heap]");
    }
    return 0;
}

static int handler_munmap_pre(struct kprobe *p, struct pt_regs *regs) {
    if (strcmp(current->comm, "malloc_test") == 0) {
        unsigned long addr = regs->di;
        unsigned long len = regs->si;
        if (len > 0) push_vma_event("MUNMAP", addr, addr + len, "---", "none");
    }
    return 0;
}

/* --- 新增 Option A 逻辑：Fork & Exec --- */

// 拦截 fork/clone 的返回。在父进程中返回子进程 PID，在子进程中返回 0。
static int handler_fork_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    long pid_or_zero = regs_return_value(regs);
    
    // 如果是 malloc_test 发起了 fork，且我们现在处于父进程上下文（pid_or_zero > 0）
    if (strcmp(current->comm, "malloc_test") == 0 && pid_or_zero > 0) {
        // 通知 Python：PID A 克隆出了 PID B
        // 这里我们将子进程 PID 放在 START_ADDR 字段，方便 Python 解析
        push_vma_event("FORK", (unsigned long)pid_or_zero, 0, "---", "child_born");
    }
    return 0;
}

// 拦截 execve (进程替换)
static int handler_exec_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    if (strcmp(current->comm, "malloc_test") == 0) {
        // 当执行 exec 时，旧的内存布局会被清空，建立全新的映射
        push_vma_event("EXEC", 0, 0, "---", "reloaded");
    }
    return 0;
}

// 探针注册
static struct kretprobe rp_mmap = { .handler = handler_mmap_ret, .kp.symbol_name = "vm_mmap_pgoff" };
static struct kretprobe rp_brk = { .handler = handler_brk_ret, .kp.symbol_name = "__x64_sys_brk" };
static struct kprobe kp_munmap = { .pre_handler = handler_munmap_pre, .symbol_name = "__x64_sys_munmap" };
static struct kretprobe rp_fork = { .handler = handler_fork_ret, .kp.symbol_name = "kernel_clone" };
static struct kretprobe rp_exec = { .handler = handler_exec_ret, .kp.symbol_name = "__x64_sys_execve" };

/* --- 基础设施 --- */

static ssize_t vma_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {
    unsigned int copied;
    if (kfifo_to_user(&my_vma_fifo, user_buf, count, &copied)) return -EFAULT;
    return copied;
}

static const struct file_operations vma_fops = { .read = vma_read };

static int __init tracker_init(void) {
    INIT_KFIFO(my_vma_fifo);
    register_kretprobe(&rp_mmap);
    register_kretprobe(&rp_brk);
    register_kprobe(&kp_munmap);
    register_kretprobe(&rp_fork);
    register_kretprobe(&rp_exec);
    
    my_vma_dir = debugfs_create_dir("vma_tracker", NULL);
    my_vma_file = debugfs_create_file("data", 0444, my_vma_dir, NULL, &vma_fops);
    return 0;
}

static void __exit tracker_exit(void) {
    unregister_kretprobe(&rp_mmap);
    unregister_kretprobe(&rp_brk);
    unregister_kprobe(&kp_munmap);
    unregister_kretprobe(&rp_fork);
    unregister_kretprobe(&rp_exec);
    debugfs_remove_recursive(my_vma_dir);
}

module_init(tracker_init);
module_exit(tracker_exit);
MODULE_LICENSE("GPL");