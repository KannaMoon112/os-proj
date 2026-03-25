#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x4efedfdd, "module_layout" },
	{ 0xbb8d98b, "param_ops_string" },
	{ 0x1e2bb696, "debugfs_remove" },
	{ 0xdd4253c7, "unregister_kretprobe" },
	{ 0x92997ed8, "_printk" },
	{ 0x888d1b1a, "debugfs_create_file" },
	{ 0x5ca4b374, "debugfs_create_dir" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0x41b7e8e2, "register_kretprobe" },
	{ 0xd9a5ea54, "__init_waitqueue_head" },
	{ 0xf31a30a6, "find_vma" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xf23fcb99, "__kfifo_in" },
	{ 0x3eeb2322, "__wake_up" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x4bbde888, "current_task" },
	{ 0xb43f9365, "ktime_get" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x92540fbf, "finish_wait" },
	{ 0x8c26d495, "prepare_to_wait_event" },
	{ 0x1000e51, "schedule" },
	{ 0xfe487975, "init_wait_entry" },
	{ 0xf37436b9, "pv_ops" },
	{ 0x4578f528, "__kfifo_to_user" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0x800473f, "__cond_resched" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "2A0D131B2A4498EDA760DAB");
