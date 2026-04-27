cmake_minimum_required(VERSION 3.10)
project(METH C)

set(CMAKE_C_STANDARD 11)

file(GLOB_RECURSE ALL_SRCS "src/*.c" "external/*.c")

add_library(meth STATIC ${ALL_SRCS})

target_include_directories(meth
    PUBLIC include
    PRIVATE external/tweetnacl
)
add_executable(meth_t test/main.c)

target_link_libraries(meth_t meth)