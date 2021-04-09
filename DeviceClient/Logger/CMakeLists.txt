set(CMAKE_CXX_STANDARD 17)
add_library(Log log.cpp log.h log_utils.h)
target_include_directories(Log PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})