Author: Lycan
Date: 20190702
Subject: Ymodel Demo使用说明


# 参考源码：

https://github.com/xiaowei942/ymodem.git
https://github.com/havenxie/stm32-iap-uart-boot.git
https://github.com/havenxie/stm32-iap-uart-app_lite.git
https://github.com/havenxie/stm32-iap-uart-app.git
https://github.com/havenxie/winapp-iap-uart.git
https://github.com/h4de5ing/MCUUpdate.git  # MCU固件升级的APK


# 我的Linux环境（WSL子系统）：

ymodem_st# lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.2 LTS
Release:        16.04
Codename:       xenial

cmake version 3.5.1
gcc/g++ (Ubuntu 4.8.5-4ubuntu2) 4.8.5


# 我的Windows环境：

Windows 10 企业版 64位
安装了Android Studio，同时配置了cmake，ndk等；
NDK version: GNU Make 3.81


# 使用CMAKE编译X86 Linux版本运用

编译命令：
mkdir build
cd build
cmake ..
make


# 使用 ndk-build 编译Android版本的运用

1, 添加Windows ndk环境变量到path中，如下：
比如，C:\Users\zengbin\AppData\Local\Android\Sdk\ndk-bundle

2，使用如下命令编译
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_APPLICATION_MK=./Application.mk

备注：
使用 "ndk-build" 即可直接编译，前提是需要将相关文件放入"jni"命名的文件下。



# 粗略使用方法：

1，STM32 MCU侧资源准备与验证

STM32 MCU Bootloader使用如下链接编译的固件；
https://github.com/havenxie/stm32-iap-uart-boot.git

STM32 MCU APP使用如下链接编译的固件；
https://github.com/havenxie/stm32-iap-uart-app.git

可以通过如下工具验证MCU固件升级通路是否正常；
https://github.com/havenxie/winapp-iap-uart.git

2，将ymodem-send 拷贝到Android文件系统中，并设置可执行权限，确保MCU和Android主控串口通路OK后执行如下命令即可；
 ./ymodem-send <MCU固件>
如: ./ymodem-send mcufw.bin


