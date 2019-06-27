Author: Lycan
Date: 20190627
Subject: Ymodel Demo使用说明


我的环境：
ymodem_st# lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.2 LTS
Release:        16.04
Codename:       xenial

cmake version 3.5.1
gcc/g++ (Ubuntu 4.8.5-4ubuntu2) 4.8.5


编译命令：
mkdir build
cd build
cmake ..
make


使用方法：
1、创建两个fifo文件，命令如下：
mkfifo /dev/myfifo
mkfifo /dev/myfifo2

2、打开两个命令终端，分别执行ymodem-send <file name> 和 ymodem-recv
终端一: ./ymodem-send Makefile
终端二: ./ymodem-recv

3、对比接收到的文件是否和源文件相同（ymodem-recv会自动创建recv.txt）
md5sum Makefile recv.txt

build# md5sum Makefile recv.txt
bcd1dba6123c153f7cd06630bb69a1ad  Makefile
bcd1dba6123c153f7cd06630bb69a1ad  recv.txt


编译日志:
root@G104E1900291:/mnt/d/Workspace/Code/MCU/ymodem_st/build# cmake ..
-- The C compiler identification is GNU 4.8.5
-- The CXX compiler identification is GNU 4.8.5
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- Check for working CXX compiler: /usr/bin/g++
-- Check for working CXX compiler: /usr/bin/g++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
** You Select To Compile A Debug Edition ~! **
-- Configuring done
-- Generating done
-- Build files have been written to: /mnt/d/Workspace/Code/MCU/ymodem_st/build


root@G104E1900291:/mnt/d/Workspace/Code/MCU/ymodem_st/build# make
Scanning dependencies of target ymodem-send
[ 25%] Building C object CMakeFiles/ymodem-send.dir/ymodem-send.c.o
[ 50%] Linking C executable ymodem-send
[ 50%] Built target ymodem-send
Scanning dependencies of target ymodem-recv
[ 75%] Building C object CMakeFiles/ymodem-recv.dir/ymodem-recv.c.o
[100%] Linking C executable ymodem-recv
[100%] Built target ymodem-recv