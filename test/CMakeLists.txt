cmake_minimum_required(VERSION 3.5)
project(OpensslppTests)

# dependencies
enable_testing()
find_package(GTest MODULE REQUIRED)
if(NOT TARGET Opensslpp::Opensslpp)
    find_package(Opensslpp CONFIG REQUIRED)
endif()

# target defintion
add_executable(OpensslppTests tests_source.cpp)
target_link_libraries(OpensslppTests
        PRIVATE
          Opensslpp::Opensslpp
          ${GTEST_BOTH_LIBRARIES}
          ${CMAKE_THREAD_LIBS_INIT} 
)
add_test(NAME Opensslpp.UnitTests
        COMMAND OpensslppTests
)
