set(CMAKE_CXX_STANDARD 17)
set(CURL_LIBRARY, "-lcurl")
find_package(CURL REQUIRED)

add_executable(EntryPoint Main.cpp
        nlohmann/json.hpp Downloader.cpp Downloader.h)

include_directories(${CURL_INCLUDE_DIR})
target_link_libraries(EntryPoint ${CURL_LIBRARIES} Log ArtifactParser ImageWriter)
install(DIRECTORY DESTINATION ${test_install})
install(TARGETS EntryPoint DESTINATION test_install)
