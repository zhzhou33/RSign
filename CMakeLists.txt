cmake_minimum_required(VERSION 3.15.0)
project(RSIGN)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set(CMAKE_CXX_EXTENSIONS OFF)

set(TARGET_NAME rsign)

set(CODE_SOURCES
    main.cpp
    RSignHelper.cpp
    RSign.cpp
)


add_executable(${TARGET_NAME} ${CODE_SOURCES})

target_include_directories(${TARGET_NAME} PRIVATE
    ./
    /usr/include/openssl
)

find_package(OpenSSL REQUIRED)
target_link_libraries(${TARGET_NAME} ${OPENSSL_LIBRARIES})
