cmake_minimum_required(VERSION 3.15)
project(ViChaos VERSION 3.0.0 LANGUAGES C)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

option(VICHAOS_BUILD_TESTS "Build unit and integration tests" ON)
option(VICHAOS_BUILD_CLI "Build CLI encrypt/decrypt tools" ON)
option(VICHAOS_BUILD_SHARED "Build shared library" ON)
option(VICHAOS_BUILD_STATIC "Build static library" ON)
option(VICHAOS_ENABLE_SANITIZERS "Enable sanitizers (ASAN/UBSAN)" OFF)
option(VICHAOS_ENABLE_COVERAGE "Enable coverage reporting" OFF)

# ---------------------------------------------------------------------------
# C standard
# ---------------------------------------------------------------------------

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Security hardening flags
# ---------------------------------------------------------------------------

add_compile_options(
    $<$<C_COMPILER_ID:GNU,Clang>:-Wall>
    $<$<C_COMPILER_ID:GNU,Clang>:-Wextra>
    $<$<C_COMPILER_ID:GNU,Clang>:-Wpedantic>
    $<$<C_COMPILER_ID:GNU,Clang>:-Werror>
    $<$<C_COMPILER_ID:GNU,Clang>:-Wformat>
    $<$<C_COMPILER_ID:GNU,Clang>:-Wformat-security>
    $<$<C_COMPILER_ID:GNU,Clang>:-fstack-protector-strong>
    $<$<C_COMPILER_ID:GNU,Clang>:-D_FORTIFY_SOURCE=2>
    $<$<C_COMPILER_ID:GNU,Clang>:-Wconversion>
    $<$<C_COMPILER_ID:GNU,Clang>:-Wsign-conversion>
)

if(VICHAOS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

if(VICHAOS_ENABLE_COVERAGE)
    add_compile_options(--coverage -fno-inline -O0)
    add_link_options(--coverage)
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------

set(VICHAOS_PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/include/vichaos.h
)

set(VICHAOS_SOURCES
    src/utils/error.c
    src/utils/version.c
    src/core/memory.c
    src/core/kdf.c
    src/core/cipher.c
    src/core/auth.c
    src/stream/stream.c
    src/vichaos.c
)

# ---------------------------------------------------------------------------
# Library targets
# ---------------------------------------------------------------------------

if(VICHAOS_BUILD_SHARED)
    add_library(vichaos_shared SHARED ${VICHAOS_SOURCES})
    set_target_properties(vichaos_shared PROPERTIES
        OUTPUT_NAME vichaos
        VERSION ${PROJECT_VERSION}
        SOVERSION 3
    )
    target_include_directories(vichaos_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_link_libraries(vichaos_shared PUBLIC OpenSSL::Crypto)
endif()

if(VICHAOS_BUILD_STATIC)
    add_library(vichaos_static STATIC ${VICHAOS_SOURCES})
    set_target_properties(vichaos_static PROPERTIES
        OUTPUT_NAME vichaos
    )
    target_include_directories(vichaos_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_link_libraries(vichaos_static PUBLIC OpenSSL::Crypto)
endif()

# ---------------------------------------------------------------------------
# CLI tools
# ---------------------------------------------------------------------------

if(VICHAOS_BUILD_CLI)
    add_executable(vichaos src/cli/vichaos_cli.c src/cli/encrypt.c src/cli/decrypt.c src/cli/cli_utils.c)
    target_compile_definitions(vichaos PRIVATE VICHAOS_UNIFIED_CLI=1)
    target_link_libraries(vichaos PRIVATE vichaos_shared)

    add_executable(vichaos_encrypt src/cli/encrypt.c src/cli/cli_utils.c)
    target_link_libraries(vichaos_encrypt PRIVATE vichaos_shared)

    add_executable(vichaos_decrypt src/cli/decrypt.c src/cli/cli_utils.c)
    target_link_libraries(vichaos_decrypt PRIVATE vichaos_shared)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(VICHAOS_BUILD_TESTS)
    enable_testing()

    # Unit tests
    function(add_vichaos_unit_test name file)
        add_executable(${name} ${file})
        target_link_libraries(${name} PRIVATE vichaos_shared)
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    add_vichaos_unit_test(test_cipher tests/unit/test_cipher.c)
    add_vichaos_unit_test(test_kdf tests/unit/test_kdf.c)
    add_vichaos_unit_test(test_stream tests/unit/test_stream.c)
    add_vichaos_unit_test(test_error tests/unit/test_error.c)
    add_vichaos_unit_test(test_memory tests/unit/test_memory.c)

    # Integration test
    add_executable(test_integration tests/integration/test_integration.c)
    target_link_libraries(test_integration PRIVATE vichaos_shared)
    add_test(NAME test_integration COMMAND test_integration)

    # Fuzz target (optional, requires libFuzzer / AFL)
    add_executable(fuzz_encrypt tests/fuzz/fuzz_encrypt.c)
    target_link_libraries(fuzz_encrypt PRIVATE vichaos_shared)
    set_target_properties(fuzz_encrypt PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

include(GNUInstallDirs)

if(VICHAOS_BUILD_CLI)
    install(TARGETS vichaos vichaos_encrypt vichaos_decrypt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(TARGETS vichaos_shared vichaos_static
    EXPORT ViChaosTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES ${VICHAOS_PUBLIC_HEADER} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT ViChaosTargets
    FILE ViChaosTargets.cmake
    NAMESPACE ViChaos::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ViChaos
)

# Generate and install pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/vichaos.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/vichaos.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/vichaos.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
