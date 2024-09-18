#!/bin/bash

# 设置源目录
SOURCE_DIR="/usr/local/freeswitch/sounds/en/us/callie"

# 获取当前日期时间，格式为 YYYYMMDD_HHMMSS
CURRENT_DATE=$(date +"%Y%m%d_%H%M%S")"_ttsfile"

# 设置目标目录，目录名包含当前日期时间信息
TARGET_DIR="${SOURCE_DIR}/${CURRENT_DATE}"

# 创建目标目录
mkdir -p "$TARGET_DIR"

# 只移动源目录下的所有文件到目标目录，排除目录
find "$SOURCE_DIR" -maxdepth 1 -type f -exec mv {} "$TARGET_DIR/" \;

# 打印完成信息
echo "All files moved from $SOURCE_DIR to $TARGET_DIR"