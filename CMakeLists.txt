cmake_minimum_required (VERSION 3.5.1)

project(computefhe CXX)
set(PROJECT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
include(GNUInstallDirs)

find_package(OpenFHE CONFIG REQUIRED)
if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif ()

if("HEXL::hexl" IN_LIST OpenFHE_SHARED_LIBRARIES)
    option( WITH_HEXL "Enable Intel HEXL support" ON)
    message(STATUS "Intel HEXL detected in OpenFHE. Setting WITH_HEXL to ON.")
else()
    option( WITH_HEXL "Enable Intel HEXL support" OFF)
    message(STATUS "Intel HEXL not found. Setting WITH_HEXL to OFF.")
endif()

if(WITH_HEXL)
    find_package(HEXL REQUIRED)
endif()

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )
include_directories( ${PROJECT_SOURCE_DIR}/include )

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

set(CORE_SOURCES
    ${PROJECT_SOURCE_DIR}/core/ComputeFHE.cpp
    ${PROJECT_SOURCE_DIR}/core/FixedPoint.cpp
    ${PROJECT_SOURCE_DIR}/core/BaseALU.cpp
    ${PROJECT_SOURCE_DIR}/core/ALUStandard.cpp
    ${PROJECT_SOURCE_DIR}/core/ALUOptimized.cpp
)

set(CPPUTILS_SOURCES
    ${PROJECT_SOURCE_DIR}/cpputils/Einteger.cpp
    ${PROJECT_SOURCE_DIR}/cpputils/ConditionManager.cpp
    ${PROJECT_SOURCE_DIR}/cpputils/Evector.cpp
    ${PROJECT_SOURCE_DIR}/cpputils/Efixedpoint.cpp
)

set(SIMULATOR_SOURCES
    ${PROJECT_SOURCE_DIR}/simulator/BaseALUSimulator.cpp
    ${PROJECT_SOURCE_DIR}/simulator/SimStandard.cpp
    ${PROJECT_SOURCE_DIR}/simulator/SimOptimized.cpp
)

set(TEST_SOURCES
    ${PROJECT_SOURCE_DIR}/tests/CFHE_Test.cpp
    ${PROJECT_SOURCE_DIR}/tests/CFHE_ALU_Test.cpp
    ${PROJECT_SOURCE_DIR}/tests/test.cpp
)

file(GLOB EXAMPLE_SOURCES "${PROJECT_SOURCE_DIR}/examples/*.cpp")

add_library(computefhe SHARED
    ${CORE_SOURCES}
    ${CPPUTILS_SOURCES}
    ${SIMULATOR_SOURCES}
)

set_target_properties(computefhe PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
)

target_include_directories(computefhe
    PRIVATE
        ${PROJECT_SOURCE_DIR}
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

install(TARGETS computefhe
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

foreach(EXAMPLE_FILE ${EXAMPLE_SOURCES})
    get_filename_component(EXE_NAME ${EXAMPLE_FILE} NAME_WE)

    set(EXE_TARGET "ex_${EXE_NAME}")
    add_executable(${EXE_TARGET} ${EXAMPLE_FILE})
    target_link_libraries(${EXE_TARGET} PRIVATE computefhe)

    set_target_properties(${EXE_TARGET} PROPERTIES
        OUTPUT_NAME "${EXE_NAME}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/examples"
    )
endforeach()

add_executable(computefhe_test
    ${TEST_SOURCES}
)

target_link_libraries(computefhe_test PRIVATE computefhe)
target_include_directories(computefhe_test
    PRIVATE
        ${PROJECT_SOURCE_DIR}/tests/include
)

find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
    message(STATUS "Found clang-format: ${CLANG_FORMAT}")
    file(GLOB_RECURSE FORMAT_SOURCES
        ${PROJECT_SOURCE_DIR}/examples/*.cpp
        ${PROJECT_SOURCE_DIR}/include/*.h
        ${PROJECT_SOURCE_DIR}/*.cpp
        ${PROJECT_SOURCE_DIR}/*.h
        ${PROJECT_SOURCE_DIR}/tests/*.cpp
        ${PROJECT_SOURCE_DIR}/tests/*.h
    )
    add_custom_target(format ALL
        COMMAND ${CLANG_FORMAT} -style=file -i ${FORMAT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Formatting sources with clang-format"
        VERBATIM
    )
else()
    message(WARNING "clang-format not found. The 'format' target will not be available.")
endif()

find_program(DOXYGEN_EXECUTABLE "doxygen")
if(DOXYGEN_EXECUTABLE)
    message(STATUS "Found doxygen: ${DOXYGEN_EXECUTABLE}")
    add_custom_target(doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
else()
    message(WARNING "doxygen not found. The 'doc' target will not be available.")
endif()
