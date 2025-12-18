savedcmd_root.mod := printf '%s\n'   main.o ftrace_helper.o | awk '!x[$$0]++ { print("./"$$0) }' > root.mod
