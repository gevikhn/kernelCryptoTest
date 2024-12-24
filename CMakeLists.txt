# 设置CMake最低版本要求
cmake_minimum_required(VERSION 3.10)

# 设置项目名称和版本
project(ProxyProject VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_VERBOSE_MAKEFILE ON)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 添加编译选项
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -O2
)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 添加源文件
set(CLIENT_SRCS 
    src/client.cpp
    src/crypto.cpp
)

set(PROXY_SRCS
    src/proxy.cpp
    src/crypto.cpp
)

# 创建可执行文件
add_executable(client ${CLIENT_SRCS})
add_executable(proxy ${PROXY_SRCS})

target_link_libraries(client PRIVATE -static)
target_link_libraries(proxy PRIVATE -static)

# 安装目标
install(TARGETS client proxy
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
) 