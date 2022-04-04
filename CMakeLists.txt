cmake_minimum_required(VERSION 3.10)
project(iboot32patcher)

# Set default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING
        "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
        FORCE)
endif(NOT CMAKE_BUILD_TYPE)

# Compiler flags
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-Ofast -fno-math-errno -fno-trapping-math")

add_library(${CMAKE_PROJECT_NAME} finders.c functions.c patchers.c)
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PUBLIC_HEADER
                      include/iBoot32Patcher/iBoot32Patcher.h)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC include)
