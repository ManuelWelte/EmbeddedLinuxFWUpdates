cmake_minimum_required(VERSION 3.3)
project(Client)
set(CMAKE_CXX_STANDARD 17)

enable_testing()

add_subdirectory(Logger)

# Comment this line out while cross-compiling
add_subdirectory(Test)
add_subdirectory(Client)
add_subdirectory(ImageWriter)
add_subdirectory(ArtifactParser)
