# Tests CMakeLists.txt
#
# GTest is optional: without it the rest of the project still configures and
# builds, and `ctest` simply reports that no tests were registered.

find_package(GTest QUIET)

if(NOT GTest_FOUND)
    message(STATUS "GTest not found - unit tests skipped "
                   "(install libgtest-dev, or configure with -DBUILD_TESTS=OFF)")
    return()
endif()

add_executable(KracKer_tests
    test_hashes.cpp
)

target_link_libraries(KracKer_tests PRIVATE
    GTest::gtest
    GTest::gtest_main
    KracKerCore
    KracKerHashesCPU
    KracKerSession
)

add_test(NAME KracKer_tests COMMAND KracKer_tests)
