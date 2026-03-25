// vma_tracker.c — LKM-based VMA event tracer
// Hooks: mmap (kretprobe), munmap (kprobe), brk (kretprobe), fork (kretprobe)
// Output: /sys/kernel/debug/vma_tracker/data (via kfifo)
// Format: ts_ns|pid|comm|op|start|end|perms|path|type

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kfifo.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/ktime.h>
#include <linux/wait.h>
#include <linux/poll.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CSC5031 Project");
MODULE_DESCRIPTION("VMA Lifecycle Tracker via kprobes");

/* ─── Configuration ─────────────────────────────────────────── */
/* Target process name filter — change via module param */
static char target_comm[TASK_COMM_LEN] = "malloc_test";
module_param_string(target_comm, target_comm, TASK_COMM_LEN, 0644);
MODULE_PARM_DESC(target_comm, "Process name to monitor (default: malloc_test)");

/* ─── kfifo ring buffer ──────────────────────────────────────── */
#define FIFO_SIZE (1 << 17)   /* 128 KB ring buffer */
static DECLARE_KFIFO(vma_fifo, char, FIFO_SIZE);
static DEFINE_SPINLOCK(fifo_lock);
static DECLARE_WAIT_QUEUE_HEAD(fifo_wq);

/* ─── Helpers ────────────────────────────────────────────────── */
static void perms_str(unsigned long flags, char *buf)
{
    buf[0] = (flags & VM_READ)  ? 'r' : '-';
    buf[1] = (flags & VM_WRITE) ? 'w' : '-';
    buf[2] = (flags & VM_EXEC)  ? 'x' : '-';
    buf[3] = '\0';
}

/*
 * Classify a VMA into a human-readable type string.
 * The frontend uses these labels for colour assignment.
 */
static const char *classify_vma(struct vm_area_struct *vma,
                                 unsigned long brk_start,
                                 unsigned long brk_end)
{
    if (!vma) return "unknown";

    /* Stack: grows downward flag or [stack] path */
    if (vma->vm_flags & VM_GROWSDOWN)
        return "stack";

    /* Heap: falls within brk region */
    if (vma->vm_start >= brk_start && vma->vm_end <= brk_end + PAGE_SIZE)
        return "heap";

    /* File-backed */
    if (vma->vm_file) {
        const char *name = vma->vm_file->f_path.dentry->d_name.name;
        /* Shared library (.so) */
        if (strstr(name, ".so"))
            return (vma->vm_flags & VM_EXEC) ? "shlib_text" : "shlib_data";
        /* Main executable text vs data */
        if (vma->vm_flags & VM_EXEC)
            return "text";
        return "data";
    }

    /* Anonymous mmap */
    if (vma->vm_flags & VM_EXEC)
        return "anon_exec";

    return "anon";
}

static void push_event(const char *op,
                       unsigned long start, unsigned long end,
                       const char *perms, const char *path,
                       const char *type)
{
    char buf[320];
    int  len;
    u64  ts = ktime_get_ns();

    len = snprintf(buf, sizeof(buf),
                   "%llu|%d|%s|%s|0x%lx|0x%lx|%s|%s|%s\n",
                   ts, current->pid, current->comm,
                   op, start, end, perms, path, type);

    spin_lock(&fifo_lock);
    if (kfifo_avail(&vma_fifo) >= (unsigned int)len)
        kfifo_in(&vma_fifo, buf, len);
    spin_unlock(&fifo_lock);

    wake_up_interruptible(&fifo_wq);
}

/* ─── kretprobe: mmap ────────────────────────────────────────── */
static int mmap_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long addr = regs_return_value(regs);
    struct vm_area_struct *vma;
    char perms[4];
    const char *path = "anon";
    const char *type;

    if (strcmp(current->comm, target_comm) != 0) return 0;
    if (!current->mm || addr >= TASK_SIZE)         return 0;

    vma = find_vma(current->mm, addr);
    if (!vma) return 0;

    perms_str(vma->vm_flags, perms);
    if (vma->vm_file)
        path = vma->vm_file->f_path.dentry->d_name.name;

    type = classify_vma(vma,
                        current->mm->start_brk,
                        current->mm->brk);
    push_event("MMAP", vma->vm_start, vma->vm_end, perms, path, type);
    return 0;
}

static struct kretprobe rp_mmap = {
    .handler       = mmap_ret,
    .kp.symbol_name = "vm_mmap_pgoff",
    .maxactive     = 20,
};

/* ─── kretprobe: brk ─────────────────────────────────────────── */
static int brk_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (strcmp(current->comm, target_comm) != 0) return 0;
    if (!current->mm) return 0;

    push_event("BRK",
               current->mm->start_brk,
               current->mm->brk,
               "rw-", "[heap]", "heap");
    return 0;
}

static struct kretprobe rp_brk = {
    .handler       = brk_ret,
    .kp.symbol_name = "__x64_sys_brk",
    .maxactive     = 20,
};

/* ─── kprobe: munmap (pre — capture args BEFORE VMA is gone) ─── */
static int munmap_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long addr, len;
    struct vm_area_struct *vma;
    char perms[4] = "---";
    const char *path = "none";
    const char *type = "anon";

    if (strcmp(current->comm, target_comm) != 0) return 0;
    if (!current->mm) return 0;

    addr = regs->di;
    len  = regs->si;
    if (!len) return 0;

    /* Try to resolve VMA metadata before it is destroyed */
    vma = find_vma(current->mm, addr);
    if (vma && vma->vm_start <= addr) {
        perms_str(vma->vm_flags, perms);
        if (vma->vm_file)
            path = vma->vm_file->f_path.dentry->d_name.name;
        type = classify_vma(vma,
                            current->mm->start_brk,
                            current->mm->brk);
    }

    push_event("MUNMAP", addr, addr + len, perms, path, type);
    return 0;
}

static struct kprobe kp_munmap = {
    .pre_handler = munmap_pre,
    .symbol_name = "__x64_sys_munmap",
};

/* ─── kretprobe: fork (Option A) ─────────────────────────────── */
static int fork_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long child_pid = regs_return_value(regs);

    if (strcmp(current->comm, target_comm) != 0) return 0;
    if (child_pid <= 0) return 0;   /* in child, return is 0 */

    /* Encode child PID in the start field; front-end uses this */
    push_event("FORK",
               (unsigned long)child_pid, 0,
               "---", "child_born", "fork");
    return 0;
}

static struct kretprobe rp_fork = {
    .handler       = fork_ret,
    .kp.symbol_name = "kernel_clone",
    .maxactive     = 20,
};

/* ─── DebugFS read (blocking) ────────────────────────────────── */
static ssize_t vma_read(struct file *file, char __user *ubuf,
                        size_t count, loff_t *ppos)
{
    unsigned int copied = 0;
    int ret;

    /* Block until data is available (or non-blocking flag set) */
    if (kfifo_is_empty(&vma_fifo)) {
        if (file->f_flags & O_NONBLOCK)
            return -EAGAIN;
        ret = wait_event_interruptible(fifo_wq, !kfifo_is_empty(&vma_fifo));
        if (ret) return ret;
    }

    spin_lock(&fifo_lock);
    ret = kfifo_to_user(&vma_fifo, ubuf, count, &copied);
    spin_unlock(&fifo_lock);

    return ret ? -EFAULT : copied;
}

static unsigned int vma_poll(struct file *file,
                              struct poll_table_struct *wait)
{
    poll_wait(file, &fifo_wq, wait);
    if (!kfifo_is_empty(&vma_fifo))
        return POLLIN | POLLRDNORM;
    return 0;
}

static const struct file_operations vma_fops = {
    .owner = THIS_MODULE,
    .read  = vma_read,
    .poll  = vma_poll,
};

/* ─── Module lifecycle ───────────────────────────────────────── */
static struct dentry *dbg_dir, *dbg_file;

static int __init tracker_init(void)
{
    int err;

    INIT_KFIFO(vma_fifo);
    init_waitqueue_head(&fifo_wq);

    if ((err = register_kretprobe(&rp_mmap)))   goto fail_mmap;
    if ((err = register_kretprobe(&rp_brk)))    goto fail_brk;
    if ((err = register_kprobe(&kp_munmap)))    goto fail_munmap;
    if ((err = register_kretprobe(&rp_fork)))   goto fail_fork;

    dbg_dir  = debugfs_create_dir("vma_tracker", NULL);
    dbg_file = debugfs_create_file("data", 0444, dbg_dir, NULL, &vma_fops);

    pr_info("vma_tracker: loaded, watching comm='%s'\n", target_comm);
    return 0;

fail_fork:   unregister_kprobe(&kp_munmap);
fail_munmap: unregister_kretprobe(&rp_brk);
fail_brk:    unregister_kretprobe(&rp_mmap);
fail_mmap:
    return err;
}

static void __exit tracker_exit(void)
{
    unregister_kretprobe(&rp_mmap);
    unregister_kretprobe(&rp_brk);
    unregister_kprobe(&kp_munmap);
    unregister_kretprobe(&rp_fork);
    debugfs_remove_recursive(dbg_dir);
    pr_info("vma_tracker: unloaded\n");
}

module_init(tracker_init);
module_exit(tracker_exit);