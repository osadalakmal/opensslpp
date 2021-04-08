cmake_minimum_required(VERSION 3.5)
project(MyLibrary)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# add project code
add_subdirectory(src)

# add unit tests
enable_testing()
add_subdirectory(test)