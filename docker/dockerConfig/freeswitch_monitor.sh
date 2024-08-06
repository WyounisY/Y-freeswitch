#!/bin/bash

# 定义日志文件路径
LOG_DIR="/usr/local/freeswitch/log"
LOG_FILE="${LOG_DIR}/freeswitch_check.log"

# 检查日志目录是否存在，不存在则创建
if [ ! -d "$LOG_DIR" ]; then
  mkdir -p "$LOG_DIR"
fi

# 无限循环
while true; do
  # 获取当前时间的小时和分钟
  CURRENT_HOUR=$(date +"%H")
  CURRENT_MINUTE=$(date +"%M")

  # 检查当前时间是否在 09:00 到 23:00 之间
  if [ "$CURRENT_HOUR" -ge 9 ] && [ "$CURRENT_HOUR" -lt 23 ]; then
    # 检测freeswitch -nc程序是否在运行
    if pgrep -f "freeswitch -nc" > /dev/null; then
      # 获取当前时间
      CURRENT_TIME=$(date +"%Y-%m-%d %H:%M:%S")
      # 打印日志到文件
      echo "[$CURRENT_TIME] freeswitch -nc is running" >> "$LOG_FILE"
    else
      # 获取当前时间
      CURRENT_TIME=$(date +"%Y-%m-%d %H:%M:%S")
      # 打印日志到文件
      echo "[$CURRENT_TIME] freeswitch -nc is not running, starting it now" >> "$LOG_FILE"
      # 启动freeswitch -nc
      freeswitch -nc
    fi
  fi

  # 检查当前时间是否为0时
  if [ "$CURRENT_HOUR" -eq 0 ] && [ "$CURRENT_MINUTE" -eq 0 ]; then
    # 获取当前时间
    CURRENT_TIME=$(date +"%Y-%m-%d %H:%M:%S")
    # 打印日志到文件
    echo "[$CURRENT_TIME] Killing sngrep and fs_cli processes" >> "$LOG_FILE"
    # 杀死包含 sngrep 和 fs_cli 的进程
    pkill -f "sngrep"
    pkill -f "fs_cli"
  fi

  # 等待60秒后再执行下一次检测
  sleep 60
done
