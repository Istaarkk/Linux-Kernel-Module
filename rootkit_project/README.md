Rootkit linux pour les version de noyau 6.X


    Ce projet existe dans un but éducatif uniquement nous ne sommes pas responsable de vos agissements ni des conséquences en cas d'utilisation malveillante de ce rootkit.



Introduction

Le but de ce projet est de réaliser un rootkit linux ainsi qu'un logiciel compagnon permettant de communiquer avec le module noyau.
Objectifs

Les objectifs de ce rootkit sont les suivants :

    La discrétion (module noyau caché, pas de logs, fichiers cachés, processus cachés, ...)
    La persistence (module noyau persistant après un reboot)
    Fonctionalités malveillante (shell root, keylogger, backdoor, ...)

Les différentes fonctionalités ainsi que son fonctionnement seront plus détaillées dans la partie Architecture.
Contexte

Après etre devenu root, on injecte le module noyau en .ko dans la machine.

Le rootkit se manifeste sur la forme d'un pilote malveillant.

Ainsi, un utlisateur (dont on fournira les identifiants) pourra intéragir avec le rootkit grace à un programme compagnon qui permettra de communiquer avec le module noyau.

Pour le contexte, la machine accepte les modules non signés.
Installation

Ce rootkit n'étant qu'un simple module noyau linux, il suffit de le compiler puis de le charger dans le noyau.

    Note : Il est recommandé de tester le rootkit sur une VM (via un dossier partagé) de façon à ne pas abimer votre propre OS/noyau.

Prérequis

docker
qemu
and other build utils see below

For debian based distros :

sudo apt install bc binutils bison dwarves flex gcc git gnupg2 gzip libelf-dev libncurses5-dev libssl-dev make openssl pahole perl-base rsync tar xz-utils qemu-system docker.io docker-cli clang

For arch based distros :

sudo pacman -S base-devel bc coreutils cpio gettext initramfs kmod libelf ncurses pahole perl python rsync tar xz qemu-full docker clang

Envrionnement de développement

Il y a deux moyens d'établir l'environnement de développpement :

    via les scripts
    via le Makefile (plus simple)

Via les scripts

Avant de tester votre rootkit il vous faudra les sources d'un noyau linux (6.X) pour compiler votre module. Pour se faire vous pouvez utiliser le script get_kernel.sh qui vous permettra de télécharger les sources du noyau.

./scripts/get_kernel.sh <version_kernel> # Exemple : ./scripts/get_kernel.sh 6.11

    Note : Vous pouvez aussi télécharger les sources du noyau via le site officiel de kernel.org.

Il vous faudra ensuite compiler votre noyau une première fois (faire y pour la configuration si elle n'a pas déjà été faite).

./scripts/compile_kernel.sh <version_kernel> # Exemple : ./scripts/compile_kernel.sh 6.11

    Note : Si vous souhaitez compiler votre noyau avec une configuration spécifique vous pouvez le faire via la commande make menuconfig dans le dossier de vos sources.

Maintenant que votre noyau est compilé il faut créer une image disque configurée avec votre noyau et la monter.

Pour se faire vous devez utiliser le script build_img.sh qui vous permettra de créer une image disque et de la monter.

./scripts/build_img.sh <kernel_version> <output_disk.img>

Puis de lancer l'image soit via le script ./scripts/run_vm.sh ./disk.img soit via la commande suivante:

qemu-system-x86_64 -hda ./disk.img -nographic -virtfs local,path=/tmp/qemu-share,mount_tag=host0,security_model=passthrough,id=host0

Un dossier partagé qui servira à transférer les modules noyau sera crée sur la machine hote dans /tmp/qemu-share qui sera accessible en lecture sur la VM dans /tmp/share
Via le Makefile

Le Makefile se base sur les scripts et sert à automatiser (ou presque) le processus

La version du noyau par défaut est la 6.11, pour spécifier une autre version il faut rajouter l'argument KERNEL=<version> après chaque commande make.

Pour afficher l'aide :

make help

Pour directement créer l'environnement en version 6.11 (compiler les sources et construire la LFS) :

make lfs
# example with args : make lfs KERNEL=6.11.2 DISK=anotherdisk.img

Pour nettoyer votre environnement de développement (les fichiers générés par la compilation du rootkit) :

make clean

Puis lancer la VM:

make run
# example with args : make run DISK=anotherdisk.img

Et enfin compiler le module et le clienlogiciel compagnon (client pour intéragir avec le rootkit) :

make

Cette commande doit se finir en créant plusieurs fichiers dont un .ko et un logiciel compagnon. Celui que nous allons charger dans notre noyau. Le fichier sera copié dans la VM si la compilation réussit.

D'autres commandes make utiles :

    Note : Il est possible de choisir la version de kernel voulue pour chaque commande make en rajoutant l'argument KERNEL= ex: make kernel KERNEL=6.11.3

Télécharger et compiler les sources :

make kernel
# example with args : make kernel KERNEL=6.11.2

Télécharger les sources :

make get_kernel
# example with args : make get_kernel KERNEL=6.11.2

Compiler les sources :

make compile_kernel
# example with args : make compile_kernel KERNEL=6.11.2

Créer l'image disque et la monter:

make deploy
# example with args : make deploy KERNEL=6.11.2 DISK=anotherdisk.img

    Note : Il est possible de choisir un nom de fichier personnalisé pour chaque commande make concernant l'image disque en rajoutant l'argument DISK=<nom de l'image disque> ex: make deploy DISK=nvo_disk.img

Uniquement créer l'image:

make disk
# example with args : make disk KERNEL=6.11.2 DISK=anotherdisk.img

Convertir l'image en qcow2:

make convert
# example with args : make convert DISK=anotherdisk.img DISK_QCOW2=anotherdisk.qcow2

Supprimer les images disques:

make clean_disk

Build

Compiler le rootkit et son logiciel compagnon

make
# example with args : make KERNEL=6.11.2

Load

Une fois le module compilé et que votre fichier .ko est bien visible vous pouvez le charger dans la VM via la commande suivante:

cd /tmp/share
insmod rootkit.ko

Unload

Pour décharger votre module de votre noyau actuel.

rmmod rootkit.ko

Logs

Si vous souhaitez voir les logs générés par votre module en mode debug.

    Pour compiler en mode debug, passer la macro RK_DEBUG de 0 à 1 dans le fichier src/rootkit/include/config.h puis recompilez

dmesg
dmesg | tail # Pour n'afficher que la fin des logs
dmesg | grep <pattern> # Pour n'afficher que certaines lignes correspondantes à une recherche

Clean

Pour nettoyer votre environnement de développement.

make clean

Logiciel compagnon

Un logiciel compagnon ou client est fourni pour intéragir avec le rootkit

Usage: 
    ientcli <operation>

Operations: 
    -h, help        Display this menu
    privesc         Give root privileges to the current user
    info            Display infos about the rootkit
    hide            Hide the rootkit from modules list
    unhide          Unhide the rootkit from module list (then allow us to remove the rootkit)

Personnalisation du rootkit

Il est possible de changer plusieurs valeurs nécessaires au rootkit:

    Le nom du pilote grace à la macro RK_DRIVER dans src/rootkit/include/config.h
    La valeur du payload pour obtenir des droits root grace à la macro RK_PRIVESC dans src/rootkit/include/config.h

Développement et contribution

Pour le développement du projet merci de vous référer à la page Comment contribuer au projet.
Architecture

Ce rootkit se découpe en deux parties bien distincte un misc device ou périphérique et une sonde kernel (kprobe).
LKM
LFS

Grace à des scripts une machine basé sur alpine linux est construite.

Elle contient : - Un utilisateur avec privilèges élevés root avec le mot de passe password - Un utilisateur normal user avec le mot de passe pass - Un dossier partagé monté dans /tmp/share sur la VM et /tmp/qemu-share sur l'host
Ressources

    Rootkit Tutorial using Vagrant
    Awesome Linux Rootkits
    Creating a Rootkit to Learn C
    kprochide
