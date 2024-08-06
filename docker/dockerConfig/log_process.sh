#!/bin/bash

# 定义日志文件目录
src_dir="/usr/local/src/log"
dest_dir="/usr/local/src/log/old_history_log"
fs_log_dir="/usr/local/freeswitch/log"

# 获取昨天的日期，格式为 YYYY-MM-DD
yesterday=$(date -d "yesterday" +"%Y-%m-%d")

# 定义要复制的日志文件
log_files=("robot_core.log" "smart_robot.log")

# 复制并重命名日志文件
for log_file in "${log_files[@]}"; do
    if [ -f "$src_dir/$log_file" ]; then
        base_name=$(basename "$log_file" .log)
        cp "$src_dir/$log_file" "$dest_dir/${base_name}_$yesterday.log"
        # 清空原始日志文件
        : > "$src_dir/$log_file"
    fi
done

# 复制并重命名 FreeSWITCH 日志文件
fs_log_file="freeswitch.log"
if [ -f "$fs_log_dir/$fs_log_file" ]; then
    cp "$fs_log_dir/$fs_log_file" "$fs_log_dir/${fs_log_file%.*}_$yesterday.log"
    # 清空原始日志文件
    : > "$fs_log_dir/$fs_log_file"
fi

#每天0时执行将前一天的日志拷贝出来 并清空原始log文件