LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := my_program
LOCAL_SRC_FILES := zuto.cc
LOCAL_LDLIBS    := -llog

include $(BUILD_EXECUTABLE)
