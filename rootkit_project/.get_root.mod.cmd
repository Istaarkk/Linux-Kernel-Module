savedcmd_get_root.mod := printf '%s\n'   get_root.o | awk '!x[$$0]++ { print("./"$$0) }' > get_root.mod
