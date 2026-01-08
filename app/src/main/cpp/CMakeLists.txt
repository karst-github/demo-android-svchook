cmake_minimum_required(VERSION 3.22.1)

project("svchook")

# 设置so文件的输出路径为当前文件所在目录下的/jniLibs中
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/jniLibs/${ANDROID_ABI})

add_library(${CMAKE_PROJECT_NAME}
        SHARED
        xhook/xh_core.c
        xhook/xh_elf.c
        xhook/xh_log.c
        xhook/xh_util.c
        xhook/xh_version.c
        xhook/xhook.c
        main.cpp)

# https://developer.android.google.cn/guide/practices/page-sizes?hl=zh-cn#cmake
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,-s,-z,max-page-size=16384")

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log)