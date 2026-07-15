cmake_minimum_required(VERSION 3.20)

project(LogLens VERSION 0.6.0 LANGUAGES CXX)

set(
    LOGLENS_VERSION_SUFFIX
    "-dev"
    CACHE STRING
    "Prerelease suffix appended to the LogLens project version"
)
set(LOGLENS_VERSION "${PROJECT_VERSION}${LOGLENS_VERSION_SUFFIX}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(LOGLENS_BUILD_FUZZERS "Build Clang libFuzzer targets" OFF)

set(LOGLENS_LIBRARY_SOURCES
    src/config.cpp
    src/parser.cpp
    src/parser/failure_classifier.cpp
    src/parser/login_handlers.cpp
    src/parser/pam_handlers.cpp
    src/parser/program_dispatch.cpp
    src/parser/source_envelope_parser.cpp
    src/parser/sshd_handlers.cpp
    src/parser/su_handlers.cpp
    src/parser/sudo_handlers.cpp
    src/parser/text_utils.cpp
    src/parser/timestamp_parser.cpp
    src/signal.cpp
    src/detector.cpp
    src/report.cpp
)

add_library(loglens_lib ${LOGLENS_LIBRARY_SOURCES})

target_include_directories(loglens_lib
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

add_executable(loglens src/main.cpp)
target_link_libraries(loglens PRIVATE loglens_lib)
target_compile_definitions(loglens PRIVATE LOGLENS_VERSION="${LOGLENS_VERSION}")

include(CTest)
if(BUILD_TESTING)
    add_executable(test_parser tests/test_parser.cpp)
    target_link_libraries(test_parser PRIVATE loglens_lib)
    add_test(NAME parser COMMAND test_parser)

    add_executable(test_parser_properties tests/test_parser_properties.cpp)
    target_link_libraries(test_parser_properties PRIVATE loglens_lib)
    add_test(NAME parser_properties COMMAND test_parser_properties)

    add_executable(test_detector tests/test_detector.cpp)
    target_link_libraries(test_detector PRIVATE loglens_lib)
    add_test(NAME detector COMMAND test_detector)

    add_executable(test_report tests/test_report.cpp)
    target_link_libraries(test_report PRIVATE loglens_lib)
    add_test(NAME report COMMAND test_report)

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

    add_executable(test_report_contracts tests/test_report_contracts.cpp)
    add_test(
        NAME report_contracts
        COMMAND test_report_contracts
            $<TARGET_FILE:loglens>
            ${CMAKE_CURRENT_BINARY_DIR}/report_contract_output
    )
endif()

if(LOGLENS_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "LOGLENS_BUILD_FUZZERS requires Clang with libFuzzer support")
    endif()

    add_library(loglens_fuzz_lib STATIC ${LOGLENS_LIBRARY_SOURCES})
    target_include_directories(loglens_fuzz_lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_options(
        loglens_fuzz_lib
        PRIVATE
            -fsanitize=fuzzer-no-link,address,undefined
            -fno-omit-frame-pointer
    )

    add_executable(fuzz_parser fuzz/parser_fuzz.cpp)
    target_link_libraries(fuzz_parser PRIVATE loglens_fuzz_lib)
    target_compile_options(
        fuzz_parser
        PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fno-omit-frame-pointer
    )
    target_link_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
