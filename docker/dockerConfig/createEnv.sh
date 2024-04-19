#!/bin/bash

# 创建目录
mkdir -p /data1/cdr /data1/logs /data1/recordings /data1/robot /data1/sms /data1/templates /data1/csv
mkdir -p /data1/robot/export /data1/robot/persistent_recording /data1/robot/robot8000 /data1/robot/temporary_recording
mkdir -p /home/work/dev/jerax
mkdir -p /home/work/tool/conf/surfin-lion-be
mkdir -p /usr/local/freeswitch/sounds/en/us/callie
chmod -R 777 /usr/local/freeswitch/sounds
# 创建JSON文件并写入内容
cat << EOF > /home/work/dev/jerax/dauntless-bay-388602-097d2323f2b3.json
{
  "google key "
}
EOF

# 设置权限为777
chmod -R 777 /data1/cdr /data1/logs /data1/recordings /data1/robot /data1/sms /data1/templates /data1/csv
chmod -R 777 /data1/robot/export /data1/robot/persistent_recording /data1/robot/robot8000 /data1/robot/temporary_recording
chmod -R 777 /home/work/dev/jerax
chmod -R 777 /home/work/tool/conf/surfin-lion-be

# 设置要导出的环境变量
# !!!!!!!!!!!!!!!!!!需要修改
# echo "export SF_ENV=dev" >> ~/.bashrc
# echo "export COUNTRY=dev" >> ~/.bashrc
# echo "export GOOGLE_APPLICATION_CREDENTIALS=/home/work/dev/jerax/dauntless-bay-388602-097d2323f2b3.json" >> ~/.bashrc

# 生效更改
# source ~/.bashrc

echo "Environment variables have been added to ~/.bashrc and activated."

# 切换到root用户
sudo su -

# 添加环境变量到.bash_profile文件末尾
# !!!!!!!!!!!!!!!!!!需要修改
echo 'SF_ENV=pro' >> /root/.bash_profile
echo 'COUNTRY=KE' >> /root/.bash_profile
echo export SF_ENV >> /root/.bash_profile
echo export COUNTRY >> /root/.bash_profile
# 刷新环境变量
source /root/.bash_profile

# 查看修改结果
echo "Root Environment variables have been added to /root/.bash_profile and activated."
echo "SF_ENV: $SF_ENV"
echo "COUNTRY: $COUNTRY"

# 退出root用户
exit


#sudo 执行脚本