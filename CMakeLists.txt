# CMake 最低版本号要求
cmake_minimum_required (VERSION 2.8)

#
set (PRONAME ymodem_api)

# 项目信息
project (${PRONAME})

# 调试
set (CMAKE_BUILD_TYPE Debug)
#set (CMAKE_BUILD_TYPE Release)

SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)
IF(${ANDROID} MATCHES "True")
    MESSAGE("Host: ${CMAKE_SYSTEM_NAME}")
    MESSAGE("Target: Android")
ENDIF()

IF (${CMAKE_BUILD_TYPE} MATCHES "Debug")
	MESSAGE("** You Select To Compile A Debug Edition ~! **")
	set(target ${PRONAME}-debug)
#	set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "g")
ELSE ()
	MESSAGE("** You Select To Compile A Release Edition ~! **")
	set(target ${PRONAME}-release)
ENDIF ()

# 加入头文件查找目录
include_directories (
	include)

# 设置源文件
set (recv_src_files
	ymodem-rcv.c)

set (send_src_files
	ymodem.cpp)

# 设置依赖库
set (thread_lib -pthread)
set (log_lib -llog)

add_executable (ymodem-recv ${recv_src_files})
add_executable (ymodem-send ${send_src_files})
