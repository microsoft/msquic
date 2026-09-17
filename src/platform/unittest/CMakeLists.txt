# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    AllocTest.cpp
    CryptTest.cpp
    DataPathTest.cpp
    PlatformTest.cpp
    # StorageTest.cpp
    ToeplitzTest.cpp
    TlsTest.cpp
)

if("${CX_PLATFORM}" STREQUAL "windows" AND
   NOT QUIC_UWP_BUILD AND
   NOT QUIC_GAMECORE_BUILD AND
   NOT ${SYSTEM_PROCESSOR} STREQUAL "arm" AND
   NOT ${SYSTEM_PROCESSOR} STREQUAL "arm64" AND
   NOT ${SYSTEM_PROCESSOR} STREQUAL "arm64ec")
    list(APPEND SOURCES RawDataPathTest.cpp)
endif()

add_executable(msquicplatformtest ${SOURCES})

target_include_directories(msquicplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquicplatformtest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")
set_property(TARGET msquicplatformtest APPEND PROPERTY BUILD_RPATH "$ORIGIN")

target_link_libraries(msquicplatformtest msquic)

if (BUILD_SHARED_LIBS)
    target_link_libraries(msquicplatformtest msquic_platform)
endif()

target_link_libraries(msquicplatformtest inc gtest warnings logging base_link)

if (WIN32)
    target_link_libraries(msquicplatformtest oldnames)
endif()

add_test(NAME msquicplatformtest
         COMMAND msquicplatformtest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
