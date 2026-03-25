cmd_/root/os-proj/kernel/Module.symvers := sed 's/\.ko$$/\.o/' /root/os-proj/kernel/modules.order | scripts/mod/modpost -m -a  -o /root/os-proj/kernel/Module.symvers -e -i Module.symvers   -T -
