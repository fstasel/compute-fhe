cmake_minimum_required (VERSION 3.5.1)

project(computefhe CXX)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

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
    src/core/ComputeFHE.cpp
    src/core/FixedPoint.cpp
    src/core/BaseALU.cpp
    src/core/ALUGateLogic.cpp
    src/core/ALUOptimized.cpp
)

set(CPPUTILS_SOURCES
    src/cpputils/Einteger.cpp
    src/cpputils/ConditionManager.cpp
    src/cpputils/Evector.cpp
    src/cpputils/Efixedpoint.cpp
)

set(SIMULATOR_SOURCES
    src/simulator/BaseALUSimulator.cpp
    src/simulator/SimGateLogic.cpp
    src/simulator/SimOptimized.cpp
)

set(TEST_SOURCES
    tests/CFHE_Test.cpp
    tests/CFHE_ALU_Test.cpp
    tests/test.cpp
)

file(GLOB EXAMPLE_SOURCES "examples/*.cpp")

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
        ${PROJECT_SOURCE_DIR}/src
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

foreach(EXAMPLE_FILE ${EXAMPLE_SOURCES})
    get_filename_component(EXE_NAME ${EXAMPLE_FILE} NAME_WE)

    set(EXE_TARGET "ex_${EXE_NAME}")
    add_executable(${EXE_TARGET} ${EXAMPLE_FILE})
    target_link_libraries(${EXE_TARGET} PRIVATE computefhe)

    set_target_properties(${EXE_TARGET} PROPERTIES
        OUTPUT_NAME "${EXE_NAME}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
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
        ${PROJECT_SOURCE_DIR}/src/*.cpp
        ${PROJECT_SOURCE_DIR}/src/*.h
        ${PROJECT_SOURCE_DIR}/tests/*.cpp
        ${PROJECT_SOURCE_DIR}/tests/*.h
    )
    add_custom_target(format ALL
        COMMAND ${CLANG_FORMAT} -style=file -i ${FORMAT_SOURCES}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Formatting sources with clang-format"
        VERBATIM
    )
else()
    message(WARNING "clang-format not found. The 'format' target will not be available.")
endif()
