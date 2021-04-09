find_package(OpenSSL REQUIRED)

add_library(ArtifactParser ArtifactParser.cpp ArtifactParser.h ArtifactCryptoHelper.h)
target_link_libraries(ArtifactParser OpenSSL::Crypto)
target_include_directories(ArtifactParser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
