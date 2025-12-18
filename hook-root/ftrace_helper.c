#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include "ftrace_helper.h"

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name;

static int resolve_hook_address(struct ftrace_hook *hook) {
    if (!my_kallsyms_lookup_name) {
        static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
        if (register_kprobe(&kp) < 0) return -ENOENT;
        my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
        unregister_kprobe(&kp);
    }

    hook->address = my_kallsyms_lookup_name(hook->name);

    if (!hook->address) return -ENOENT;

    *(unsigned long *)hook->original = hook->address;
    return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                 struct ftrace_ops *ops, struct ftrace_regs *fregs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);
    regs->ip = (unsigned long)hook->function;
}

static int install_hook(struct ftrace_hook *hook) {
    int err;
    
    err = resolve_hook_address(hook);
    if (err) return err;
    
    hook->ops.func = ftrace_thunk;
    
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                      FTRACE_OPS_FL_RECURSION |
                      FTRACE_OPS_FL_IPMODIFY;
    
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) return err;
    
    err = register_ftrace_function(&hook->ops);
    if (err) {
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }
    
    return 0;
}

static void remove_hook(struct ftrace_hook *hook) {
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
    int err;
    size_t i;
    
    for (i = 0; i < count; i++) {
        err = install_hook(&hooks[i]);
        if (err) {
            while (i != 0) remove_hook(&hooks[--i]);
            return err;
        }
    }
    
    return 0;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) remove_hook(&hooks[i]);
}