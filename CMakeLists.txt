cmake_minimum_required(VERSION 3.16)
project(cord_craft C)

set(CMAKE_C_STANDARD 23)

# ---------------------------------------------------------------------
# collect sources and build the static library
# ---------------------------------------------------------------------
file(GLOB_RECURSE SOURCES "src/*.c")
add_library(cord_craft STATIC ${SOURCES})

# ---------------------------------------------------------------------
# public include paths
#   • build tree : <repo>/include/cord_craft
#   • install    : <prefix>/include/cord_craft
# ---------------------------------------------------------------------
target_include_directories(cord_craft
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ---------------------------------------------------------------------
# install rules
# ---------------------------------------------------------------------
install(TARGETS cord_craft DESTINATION lib)
install(DIRECTORY include/cord_craft DESTINATION include)
