cmake_minimum_required(VERSION 3.5)
project(Opensslpp VERSION 0.0.1)

file(GLOB_RECURSE SRCS *.cpp)
file(GLOB_RECURSE HEADERS *.h)

add_library(Opensslpp ${SRCS} ${HEADERS})

find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
  target_include_directories(Opensslpp PUBLIC ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(Opensslpp OpenSSL::SSL OpenSSL::Crypto)
  message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
endif()

install(TARGETS Opensslpp EXPORT OpensslppTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)
install(EXPORT OpensslppTargets
        DESTINATION lib/cmake/Opensslpp
        FILE OpensslppTargets.cmake
        NAMESPACE Opensslpp::)
install(DIRECTORY include/Opensslpp
        DESTINATION include)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(OpensslppConfigVersion.cmake
        COMPATIBILITY SameMajorVersion)
install(FILES OpensslppConfig.cmake ${CMAKE_CURRENT_BINARY_DIR}/OpensslppConfigVersion.cmake
        DESTINATION lib/cmake/Opensslpp)

target_compile_features(Opensslpp PUBLIC cxx_std_17)
target_include_directories(Opensslpp PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)
add_library(Opensslpp::Opensslpp ALIAS Opensslpp)
