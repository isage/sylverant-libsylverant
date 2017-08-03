cmake_minimum_required(VERSION 2.6)


include(CheckCCompilerFlag)

project(libsylverant)

set (libsylverant_VERSION_MAJOR 1)
set (libsylverant_VERSION_MINOR 0)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(LibXml2)
find_package(MYSQL)

include_directories(${LIBXML2_INCLUDE_DIR})
include_directories(${MYSQL_INCLUDE_DIRS})

file(GLOB DB_SOURCES "src/database/[a-zA-Z]*.c")
file(GLOB ENC_SOURCES "src/encryption/[a-zA-Z]*.c")
file(GLOB SSL_SOURCES "src/polarssl/[a-zA-Z]*.c")
file(GLOB UTIL_SOURCES "src/utils/[a-zA-Z]*.c")

set(SOURCES
    ${DB_SOURCES}
    ${ENC_SOURCES}
    ${SSL_SOURCES}
    ${UTIL_SOURCES}
)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_definitions(-DDATAROOTDIR="${CMAKE_INSTALL_PREFIX}/share")

option(DEBUG "build application with debug traces" OFF) # OFF is the default

if(DEBUG)
  add_definitions(-DTRACE_SCRIPT)
endif(DEBUG)

add_definitions("-Wall")
add_library(sylverant SHARED ${SOURCES})
target_link_libraries(sylverant ${LIBXML2_LIBRARIES} ${MYSQL_LIBRARIES})



