cmake_minimum_required(VERSION 3.10)
project(KracKer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(include)

add_executable(KracKer
    src/main.cpp
    src/cracker.cpp
    src/hash.cpp
)

target_link_libraries(KracKer OpenSSL::SSL OpenSSL::Crypto pthread)

install(TARGETS KracKer DESTINATION /usr/local/bin)
