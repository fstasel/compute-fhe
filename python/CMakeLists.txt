cmake_minimum_required(VERSION 3.18)
project(computefhe_python LANGUAGES CXX)

find_package(Python COMPONENTS Interpreter Development.Module REQUIRED)
find_package(pybind11 CONFIG REQUIRED)
find_package(OpenFHE CONFIG REQUIRED)
find_package(ComputeFHE CONFIG REQUIRED)

pybind11_add_module(_native native/bindings.cpp)
target_compile_features(_native PRIVATE cxx_std_17)
# Upstream's exported target does not propagate all OpenFHE include paths.
target_include_directories(_native PRIVATE
    "${OpenFHE_INCLUDE}/.." "${OpenFHE_INCLUDE}"
    "${OpenFHE_INCLUDE}/third-party/include" "${OpenFHE_INCLUDE}/core"
    "${OpenFHE_INCLUDE}/pke" "${OpenFHE_INCLUDE}/binfhe")
target_link_directories(_native PRIVATE "${OpenFHE_LIBDIR}")
target_link_libraries(_native PRIVATE ComputeFHE::computefhe ${OpenFHE_SHARED_LIBRARIES})
if(OpenFHE_CXX_FLAGS)
    separate_arguments(OPENFHE_COMPILE_OPTIONS NATIVE_COMMAND "${OpenFHE_CXX_FLAGS}")
    target_compile_options(_native PRIVATE ${OPENFHE_COMPILE_OPTIONS})
endif()
set_target_properties(_native PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
install(TARGETS _native LIBRARY DESTINATION computefhe)
