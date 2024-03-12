
cmake_minimum_required(VERSION 3.16)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

project(pns)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(pns STATIC
    pns/hivemind.cpp
    pns/pg.cpp
    pns/swarmpubkey.cpp
    pns/utils.cpp
    pns/hive/signature.cpp
    pns/hive/snode.cpp
    pns/hive/subscription.cpp
)

find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)
pkg_check_modules(OXENC REQUIRED IMPORTED_TARGET liboxenc>=1.0.4)
pkg_check_modules(OXENMQ REQUIRED IMPORTED_TARGET liboxenmq>=1.2.14)
pkg_check_modules(NLOHMANN_JSON REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)

if(CMAKE_VERSION VERSION_LESS "3.21")
    # Work around cmake bug 22180 (PkgConfig::THING not set if no flags needed)
    add_library(_deps_dummy INTERFACE)
    foreach(pkg OXENC NLOHMANN_JSON)
        if(NOT TARGET PkgConfig::${pkg})
            add_library(PkgConfig::${pkg} ALIAS _deps_dummy)
        endif()
    endforeach()
endif()

option(SUBMODULE_CHECK "Enables checking that vendored library submodules are up to date" ON)
if(SUBMODULE_CHECK)
  find_package(Git)
  if(GIT_FOUND)
    function(check_submodule relative_path)
      execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE localHead)
      execute_process(COMMAND git rev-parse "HEAD:${relative_path}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE checkedHead)
      string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
      if (upToDate)
        message(STATUS "Submodule '${relative_path}' is up-to-date")
      else()
        message(FATAL_ERROR "Submodule '${relative_path}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
      endif()

      # Extra arguments check nested submodules
      foreach(submod ${ARGN})
        execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/${submod} OUTPUT_VARIABLE localHead)
        execute_process(COMMAND git rev-parse "HEAD:${submod}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE checkedHead)
        string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
        if (NOT upToDate)
            message(FATAL_ERROR "Nested submodule '${relative_path}/${submod}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
        endif()
      endforeach()
    endfunction ()

    message(STATUS "Checking submodules")
    check_submodule(oxen-logging fmt spdlog)
    check_submodule(libpqxx)
    check_submodule(pybind11)

  endif()
endif()

set(OXEN_LOGGING_SOURCE_ROOT "${PROJECT_SOURCE_DIR}" CACHE INTERNAL "")
add_subdirectory(oxen-logging)

add_subdirectory(libpqxx EXCLUDE_FROM_ALL)

target_link_libraries(pns PRIVATE
    PkgConfig::SODIUM
    PkgConfig::OXENC
    PkgConfig::OXENMQ
    PkgConfig::SYSTEMD
    PUBLIC
    pqxx
    oxen::logging)

set_target_properties(pns PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)

set(PYBIND11_FINDPYTHON ON CACHE INTERNAL "")
add_subdirectory(pybind11)
pybind11_add_module(
    core
    pns/pybind.cpp)

target_link_libraries(core PUBLIC pns)
set_target_properties(core PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/pns)
