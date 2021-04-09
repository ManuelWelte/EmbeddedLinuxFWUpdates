set(CMAKE_CXX_STANDARD 17)
add_library(ImageWriter Writer.cpp Writer.h)
target_include_directories(ImageWriter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})