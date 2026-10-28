cmake_minimum_required(VERSION 3.20)
project(KracKer VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build types
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Options
option(BUILD_TESTS "Build unit tests (skipped when GTest is missing)" ON)
option(WITH_OPENCL "Enable the experimental OpenCL backend" OFF)
option(WITH_CUDA "Enable the experimental CUDA backend" OFF)
option(WITH_ARGON2 "Enable Argon2 support (needs libargon2)" ON)
option(WITH_BCRYPT "Enable bcrypt support via libxcrypt" ON)
option(WITH_DISTRIBUTED "Enable distributed cracking (not implemented)" OFF)
option(WITH_TLS "Enable TLS for distributed mode" OFF)

# Platform detection
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_compile_definitions(KK_PLATFORM_WINDOWS=1 KK_WIN32=1)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /bigobj")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_compile_definitions(KK_PLATFORM_MACOS=1)
else()
    add_compile_definitions(KK_PLATFORM_LINUX=1)
endif()

# Compiler warnings. /WX is deliberately not set: OpenSSL 3 deprecates some
# of the low-level primitives this project still calls directly.
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

# Find packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# OpenCL
if(WITH_OPENCL)
    find_package(OpenCL QUIET)
    if(OPENCL_FOUND)
        add_compile_definitions(KK_HAVE_OPENCL=1)
        message(STATUS "OpenCL found: ${OPENCL_LIBRARIES}")
    else()
        message(WARNING "OpenCL not found, GPU acceleration disabled")
        set(WITH_OPENCL OFF)
    endif()
endif()

# CUDA (experimental; never required - absent CUDA simply disables the backend)
if(WITH_CUDA)
    find_package(CUDA QUIET)
    if(CUDA_FOUND)
        message(STATUS "CUDA found: ${CUDA_VERSION}")
        enable_language(CUDA)
        add_compile_definitions(KK_HAVE_CUDA=1)
    else()
        message(STATUS "CUDA not found - CUDA backend disabled")
        set(WITH_CUDA OFF)
    endif()
endif()

# Argon2 (optional, external library)
if(WITH_ARGON2)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(ARGON2 QUIET argon2)
    endif()
    if(ARGON2_FOUND)
        add_compile_definitions(KK_HAVE_ARGON2=1)
        message(STATUS "Argon2 found: ${ARGON2_VERSION}")
    else()
        message(STATUS "Argon2 not found (install libargon2-dev) - Argon2 hashes disabled")
        set(WITH_ARGON2 OFF)
    endif()
endif()

# scrypt is provided by OpenSSL's EVP_PBE_scrypt(); no extra dependency.
# bcrypt is provided by libxcrypt below.

# bcrypt (built-in implementation)
if(WITH_BCRYPT)
    add_compile_definitions(KK_HAVE_BCRYPT=1)
endif()

# ASIO is only needed by the (currently disabled) distributed transport.
if(WITH_DISTRIBUTED)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(ASIO QUIET asio)
    endif()
    if(NOT ASIO_FOUND)
        find_path(ASIO_INCLUDE_DIR asio.hpp
            PATHS /usr/include /usr/local/include /opt/homebrew/include
        )
    endif()
    if(ASIO_FOUND OR ASIO_INCLUDE_DIR)
        add_compile_definitions(ASIO_STANDALONE=1)
        message(STATUS "ASIO found")
    else()
        message(STATUS "ASIO not found (install libasio-dev) - distributed mode cannot be built")
        set(WITH_DISTRIBUTED OFF)
    endif()
endif()

# nlohmann/json for config/session. Header-only; fall back to FetchContent
# only when the system package is absent.
find_package(nlohmann_json 3.10.0 QUIET)
if(nlohmann_json_FOUND)
    message(STATUS "nlohmann_json found: ${nlohmann_json_VERSION}")
else()
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(NLOHMANN_JSON QUIET nlohmann_json)
    endif()
    if(NLOHMANN_JSON_FOUND)
        message(STATUS "nlohmann_json found via pkg-config")
    else()
        message(STATUS "nlohmann_json not found - fetching v3.11.2 (needs network)")
        include(FetchContent)
        FetchContent_Declare(
            nlohmann_json
            GIT_REPOSITORY https://github.com/nlohmann/json.git
            GIT_TAG v3.11.2
        )
        FetchContent_MakeAvailable(nlohmann_json)
    endif()
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Core library - only files that actually exist
add_library(KracKerCore STATIC
    src/core/hash_registry.cpp
    src/core/cracker.cpp
    src/core/config.cpp
    src/core/utils.cpp
    src/core/wordlist.cpp
    src/core/mask.cpp
    src/core/rules.cpp
)

target_link_libraries(KracKerCore PUBLIC
    OpenSSL::SSL OpenSSL::Crypto
    Threads::Threads
    KracKerHashesCPU
)

# Add nlohmann_json if found
if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(KracKerCore PUBLIC nlohmann_json::nlohmann_json)
elseif(NLOHMANN_JSON_FOUND)
    target_include_directories(KracKerCore PUBLIC ${NLOHMANN_JSON_INCLUDE_DIRS})
else()
    message(FATAL_ERROR
        "nlohmann_json is required but was not found.\n"
        "Install it (Debian/Ubuntu: sudo apt install nlohmann-json3-dev) "
        "or re-run CMake with network access so FetchContent can download it.")
endif()

# Add ASIO if the distributed backend is enabled
if(WITH_DISTRIBUTED)
    if(ASIO_FOUND)
        target_include_directories(KracKerCore PUBLIC ${ASIO_INCLUDE_DIRS})
    elseif(ASIO_INCLUDE_DIR)
        target_include_directories(KracKerCore PUBLIC ${ASIO_INCLUDE_DIR})
    endif()
endif()

target_include_directories(KracKerCore PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# CPU Hash implementations - only files that exist
add_library(KracKerHashesCPU STATIC
    src/hashes/cpu/hash_md5.cpp
    src/hashes/cpu/hash_sha1.cpp
    src/hashes/cpu/hash_sha2.cpp
    src/hashes/cpu/hash_ntlm.cpp
    src/hashes/cpu/hash_bcrypt.cpp
    src/hashes/cpu/hash_scrypt.cpp
    src/hashes/cpu/hash_argon2.cpp
    src/hashes/cpu/hash_kerberoast.cpp
)

target_link_libraries(KracKerHashesCPU PUBLIC KracKerCore)

if(ARGON2_FOUND)
    target_link_libraries(KracKerHashesCPU PUBLIC ${ARGON2_LIBRARIES})
    target_include_directories(KracKerHashesCPU PUBLIC ${ARGON2_INCLUDE_DIRS})
endif()

# bcrypt via libxcrypt. Only the runtime library is needed (no dev headers):
# the reentrant crypt_rn()/crypt_gensalt_rn() API is declared locally.
find_library(CRYPT_LIBRARY NAMES libcrypt.so.1 crypt)
if(CRYPT_LIBRARY)
    target_link_libraries(KracKerHashesCPU PUBLIC ${CRYPT_LIBRARY})
    target_compile_definitions(KracKerHashesCPU PUBLIC KK_HAVE_CRYPT=1)
else()
    message(WARNING "libcrypt not found - bcrypt support will be disabled")
endif()

# GPU Hash implementations (OpenCL) - only files that exist
if(WITH_OPENCL)
    add_library(KracKerHashesOpenCL
        src/hashes/gpu/opencl_context.cpp
        src/hashes/gpu/hash_opencl_md5.cpp
        src/hashes/gpu/hash_opencl_sha1.cpp
        src/hashes/gpu/hash_opencl_sha2.cpp
    )
    target_link_libraries(KracKerHashesOpenCL PUBLIC KracKerCore OpenCL::OpenCL)
    target_include_directories(KracKerHashesOpenCL PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
endif()

# GPU Hash implementations (CUDA) - only files that exist
if(WITH_CUDA)
    add_library(KracKerHashesCUDA
        src/hashes/gpu/cuda_context.cpp
        src/hashes/gpu/cuda_md5.cu
        src/hashes/gpu/cuda_sha1.cu
        src/hashes/gpu/cuda_sha2.cu
        src/hashes/gpu/cuda_ntlm.cu
    )
    target_link_libraries(KracKerHashesCUDA PUBLIC KracKerCore ${CUDA_LIBRARIES})
    target_include_directories(KracKerHashesCUDA PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(KracKerHashesCUDA PROPERTIES CUDA_SEPARABLE_COMPILATION ON)
endif()

# Attack modes - not built: the engine drives attack modes directly from
# src/core/cracker.cpp, so src/attacks/*.cpp are not compiled.

# Session management - only files that exist
add_library(KracKerSession
    src/session/session_manager.cpp
)
target_link_libraries(KracKerSession PUBLIC KracKerCore)

# Distributed cracking - disabled for now due to incomplete implementation
# if(WITH_DISTRIBUTED)
#     add_library(KracKerDistributed
#         src/distributed/distributed.cpp
#     )
#     target_link_libraries(KracKerDistributed PUBLIC KracKerCore KracKerSession)
#     if(WITH_TLS)
#         target_link_libraries(KracKerDistributed PUBLIC OpenSSL::SSL OpenSSL::Crypto)
#         add_compile_definitions(KK_HAVE_TLS=1)
#     endif()
# endif()

# CLI executable - only files that exist
add_executable(KracKer
    src/cli/main.cpp
)

target_link_libraries(KracKer PRIVATE
    KracKerCore
    KracKerHashesCPU
    KracKerSession
)

if(WITH_OPENCL)
    target_link_libraries(KracKer PRIVATE KracKerHashesOpenCL)
endif()

if(WITH_CUDA)
    target_link_libraries(KracKer PRIVATE KracKerHashesCUDA)
endif()

# Distributed linking disabled for now
# if(WITH_DISTRIBUTED)
#     target_link_libraries(KracKer PRIVATE KracKerDistributed)
# endif()

# Install targets
install(TARGETS KracKer DESTINATION bin)

install(TARGETS KracKerCore KracKerHashesCPU KracKerSession
        EXPORT KracKerTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

if(WITH_OPENCL)
    install(TARGETS KracKerHashesOpenCL
        EXPORT KracKerTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)
endif()

if(WITH_CUDA)
    install(TARGETS KracKerHashesCUDA
        EXPORT KracKerTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)
endif()

install(DIRECTORY include/ DESTINATION include
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")

install(FILES README.md LICENSE DESTINATION share/doc/KracKer OPTIONAL)

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Package config: the export file must not be called KracKerConfig.cmake,
# otherwise it collides with the generated package config below.
include(CMakePackageConfigHelpers)

install(EXPORT KracKerTargets
        FILE KracKerTargets.cmake
        NAMESPACE KracKer::
        DESTINATION lib/cmake/KracKer)

set(KRACKER_WITH_OPENCL ${WITH_OPENCL})
set(KRACKER_WITH_CUDA ${WITH_CUDA})
set(KRACKER_WITH_DISTRIBUTED ${WITH_DISTRIBUTED})
set(KRACKER_WITH_ARGON2 ${WITH_ARGON2})

write_basic_package_version_file(
    ${CMAKE_BINARY_DIR}/KracKerConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    cmake/KracKerConfig.cmake.in
    ${CMAKE_BINARY_DIR}/KracKerConfig.cmake
    INSTALL_DESTINATION lib/cmake/KracKer
)

install(FILES
        ${CMAKE_BINARY_DIR}/KracKerConfig.cmake
        ${CMAKE_BINARY_DIR}/KracKerConfigVersion.cmake
        DESTINATION lib/cmake/KracKer)

# CPack for packaging
include(CPack)
set(CPACK_PACKAGE_NAME "KracKer")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Cross-platform CPU hash cracker with session resume")
set(CPACK_PACKAGE_VENDOR "KracKer Project")
set(CPACK_GENERATOR "TGZ;DEB;RPM")