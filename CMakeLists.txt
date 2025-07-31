cmake_minimum_required(VERSION 3.20)
project(cord_craft  LANGUAGES C)

# INTERFACE library for headers-only or future expansion
add_library(cord_craft INTERFACE)

target_include_directories(cord_craft INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

