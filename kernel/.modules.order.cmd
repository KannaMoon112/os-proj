cmd_/root/os-proj/kernel/modules.order := {   echo /root/os-proj/kernel/vma_tracker.ko; :; } | awk '!x[$$0]++' - > /root/os-proj/kernel/modules.order
