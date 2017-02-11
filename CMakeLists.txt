cmake_minimum_required(VERSION 3.0.2)
project(libwireshark C)
set(CMAKE_BUILD_TYPE Debug)


set( CM_VERSION_MAJOR    0 )
set( CM_VERSION_MINOR    0 )
set( CM_VERSION_SUBMINOR 2 )

include( CMakePackageConfigHelpers )


if(MSVC)
  # Force to always compile with W4
  if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUC)
  # Update if necessary
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -pedantic -std=gnu11 -fPIC")
endif()

set( CMAKE_POSITION_INDEPENDENT_CODE ON )

find_package( Wireshark REQUIRED )
find_package( PkgConfig REQUIRED )
pkg_search_module(GLIB REQUIRED glib-2.0)

message( STATUS "Wireshark version:     ${Wireshark_VERSION_STRING}" )
message( STATUS "Wireshark install dir: ${Wireshark_INSTALL_DIR}" )

include_directories( SYSTEM ${Wireshark_INCLUDE_DIR} ${GLIB_INCLUDE_DIRS} )
include_directories(        ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_CURRENT_LIST_DIR}/include )
link_directories( ${Wireshark_LIB_DIR} )

set(CMAKE_MACOSX_RPATH 1)


set(src
  ${CMAKE_CURRENT_SOURCE_DIR}/frame_tvbuff.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ws_dissect.c
  ${CMAKE_CURRENT_SOURCE_DIR}/print_stream_mem.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ws_capture.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cfile.c
)

set(header
  ${CMAKE_CURRENT_SOURCE_DIR}/frame_tvbuff.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ws_dissect.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ws_capture.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cfile.h
)

# this is the "object library" target: compiles the sources only once
add_library(objlib OBJECT ${src} ${header})

# actual shared and static libraries built from the same object files
add_library(${PROJECT_NAME}        SHARED $<TARGET_OBJECTS:objlib>)
add_library(${PROJECT_NAME}_static STATIC $<TARGET_OBJECTS:objlib>)

set_target_properties(
  ${PROJECT_NAME} ${PROJECT_NAME}_static
  PROPERTIES
    VERSION       ${CM_VERSION_MAJOR}.${CM_VERSION_MINOR}.${CM_VERSION_SUBMINOR}
    SOVERSION     ${CM_VERSION_MAJOR}
    PUBLIC_HEADER "${header}"
    OUTPUT_NAME   "${PROJECT_NAME}"
)

add_definitions(-DWS_NORETURN=_Noreturn)

target_link_libraries(${PROJECT_NAME} ${Wireshark_LIBRARY} wiretap wsutil ${GLIB_LIBRARIES})

# examples
# 0
file(GLOB simple_print_src examples/00-simple-print.c)
add_executable(simple_print ${simple_print_src})
target_compile_options(simple_print PUBLIC ${GLIB_CFLAGS_OTHER})
target_link_libraries(simple_print ${PROJECT_NAME} ${GLIB_LIBRARIES})
# 1
file(GLOB seek_offline_src examples/01-seek-interactive-offline.c)
add_executable(seek_offline ${seek_offline_src})
target_compile_options(seek_offline PUBLIC ${GLIB_CFLAGS_OTHER})
target_link_libraries(seek_offline ${PROJECT_NAME} ${GLIB_LIBRARIES})
# 2
file(GLOB seek_online_src examples/02-seek-interactive-online.c)
MESSAGE(STATUS ${seek_online_src})
add_executable(seek_online ${seek_online_src})
target_compile_options(seek_online PUBLIC ${GLIB_CFLAGS_OTHER})
target_link_libraries(seek_online ${PROJECT_NAME} ${GLIB_LIBRARIES})

# install
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake"
    VERSION       ${CM_VERSION_MAJOR}.${CM_VERSION_MINOR}.${CM_VERSION_SUBMINOR}
    COMPATIBILITY SameMajorVersion
)

install( TARGETS ${PROJECT_NAME} ${PROJECT_NAME}_static simple_print seek_offline seek_online
  EXPORT        ${PROJECT_NAME}Targets
  RUNTIME       DESTINATION bin
  ARCHIVE       DESTINATION lib
  LIBRARY       DESTINATION lib
  PUBLIC_HEADER DESTINATION include/libwireshark
)

install( EXPORT ${PROJECT_NAME}Targets DESTINATION lib/cmake/${PROJECT_NAME} )
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake
    ${PROJECT_SOURCE_DIR}/${PROJECT_NAME}Config.cmake
  DESTINATION lib/cmake/${PROJECT_NAME}
)

IF(EXISTS ${CMAKE_CURRENT_LIST_DIR}/private.cmake)
    include(${CMAKE_CURRENT_LIST_DIR}/private.cmake)
ENDIF()
