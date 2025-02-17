#!/bin/bash

# 获取所有 PID 大于等于 1000 且程序名是 "bash" 的进程
pids=$(ps aux | awk '$2 >= 1000 && $11 == "bash" {print $2}')

# 检查是否有符合条件的进程
if [ -z "$pids" ]; then
    echo "没有找到符合条件的进程。"
    exit 0
fi

# 杀掉这些进程
echo "正在杀掉以下进程："
echo "$pids"
kill -9 $pids

# 检查是否成功
if [ $? -eq 0 ]; then
    echo "进程已成功终止。"
else
    echo "终止进程时出错。"
fi