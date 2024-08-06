1. 执行检查freeswitch是否在线 以及每天0时kill 无用的程序
nohup ./freeswitch_monitor.sh  & 

2. 执行每天0时将log复制 并清空
0 0 * * * /usr/local/freeswitch/scripts/log_process.sh