cmake_minimum_required(VERSION 3.20)

project(LogLens VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(loglens_lib
    src/config.cpp
    src/parser.cpp
    src/signal.cpp
    src/detector.cpp
    src/report.cpp
)

target_include_directories(loglens_lib
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

add_executable(loglens src/main.cpp)
target_link_libraries(loglens PRIVATE loglens_lib)

include(CTest)
if(BUILD_TESTING)
    add_executable(test_parser tests/test_parser.cpp)
    target_link_libraries(test_parser PRIVATE loglens_lib)
    add_test(NAME parser COMMAND test_parser)

    add_executable(test_detector tests/test_detector.cpp)
    target_link_libraries(test_detector PRIVATE loglens_lib)
    add_test(NAME detector COMMAND test_detector)

    add_executable(test_cli tests/test_cli.cpp)
    target_link_libraries(test_cli PRIVATE loglens_lib)
    add_test(
        NAME cli
        COMMAND test_cli
            $<TARGET_FILE:loglens>
            ${CMAKE_CURRENT_SOURCE_DIR}/assets/sample_auth.log
            ${CMAKE_CURRENT_SOURCE_DIR}/assets/sample_config.json
            ${CMAKE_CURRENT_BINARY_DIR}/cli_test_output
    )
endif()
