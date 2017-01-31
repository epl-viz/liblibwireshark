cmake_minimum_required(VERSION 3.0.2)
project(libwireshark C)
set(CMAKE_BUILD_TYPE Debug)

if(MSVC)
  # Force to always compile with W4
  if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUC)
  # Update if necessary
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -pedantic -std=c99")
endif()

include_directories(include)
include_directories(.)
include_directories(SYSTEM ~/pse/wireshark)

set(CMAKE_MACOSX_RPATH 1) 

set(src frame_tvbuff.c ws_dissect.c ws_capture.c cfile.c)
# this is the "object library" target: compiles the sources only once
add_library(objlib OBJECT ${src})
# shared libraries need PIC
set_property(TARGET ${objlib} PROPERTY POSITION_INDEPENDENT_CODE 1)
# actual shared and static libraries built from the same object files
add_library(libwireshark SHARED $<TARGET_OBJECTS:objlib>)
add_library(libwireshark_static STATIC $<TARGET_OBJECTS:objlib>)

add_definitions(-DWS_NORETURN=_Noreturn)

find_package(PkgConfig REQUIRED)
pkg_search_module(LIBWIRESHARK REQUIRED wireshark)
pkg_search_module(GLIB REQUIRED glib-2.0)

target_include_directories(objlib PUBLIC ${LIBWIRESHARK_INCLUDE_DIRS})
target_compile_options(objlib PUBLIC ${LIBWIRESHARK_CFLAGS_OTHER})
target_link_libraries(libwireshark ${LIBWIRESHARK_LIBRARIES})

target_link_libraries(libwireshark wiretap)
target_link_libraries(libwireshark wsutil)

# examples
file(GLOB simple_print_src examples/00-simple-print.c)
add_executable(simple_print ${simple_print_src})
target_include_directories(simple_print PUBLIC ${GLIB_INCLUDE_DIRS})
target_compile_options(simple_print PUBLIC ${GLIB_CFLAGS_OTHER})
target_link_libraries(simple_print libwireshark ${GLIB_LIBRARIES})

