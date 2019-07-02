LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := ymodem-send
LOCAL_SRC_FILES := ymodem-send.c

include $(BUILD_EXECUTABLE)
