cmake_minimum_required(VERSION 3.0.2)

project(libwireshark
            VERSION 1.0.1
            LANGUAGES C)

enable_testing()

set( CM_VERSION_MAJOR    0 )
set( CM_VERSION_MINOR    0 )
set( CM_VERSION_SUBMINOR 2 )

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR})

set(CMAKE_C_STANDARD 11)

if(WIN32)
  set(WIRESHARK_TARGET_PLATFORM win64)
  set(PROCESSOR_ARCHITECTURE amd64)
endif(WIN32)

if( WIRESHARK_BASE_DIR )
  set( ENV{WIRESHARK_BASE_DIR} "${WIRESHARK_BASE_DIR}" )
  set( ENV{WIRESHARK_LIB_DIR}  "${WIRESHARK_BASE_DIR}/wireshark-${WIRESHARK_TARGET_PLATFORM}-libs-2.4" )
endif( WIRESHARK_BASE_DIR )

include( CMakePackageConfigHelpers )

option( ENABLE_EXAMPLES "Enables the example exes" ON )

if(MSVC)
  # Force to always compile with W4
  if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUC)
  # Update if necessary
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -std=gnu11 -fPIC -fdiagnostics-color=always")
endif()

set( CMAKE_POSITION_INDEPENDENT_CODE ON )

find_package( Wireshark REQUIRED )
find_package( GLIB2     REQUIRED )
find_package( PCAP      REQUIRED )

message( STATUS "Wireshark version:     ${Wireshark_VERSION_STRING}" )
message( STATUS "Wireshark install dir: ${Wireshark_INSTALL_DIR}" )

include_directories( SYSTEM ${Wireshark_INCLUDE_DIR} ${GLIB2_INCLUDE_DIRS} ${PCAP_INCLUDE_DIR})
include_directories(        ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_CURRENT_LIST_DIR}/include )
link_directories( ${Wireshark_LIB_DIR} )

IF(EXISTS ${CMAKE_CURRENT_LIST_DIR}/private.cmake)
    include(${CMAKE_CURRENT_LIST_DIR}/private.cmake)
ENDIF()


set(CMAKE_MACOSX_RPATH 1)


set(src
  ${CMAKE_CURRENT_SOURCE_DIR}/dissect.c
  ${CMAKE_CURRENT_SOURCE_DIR}/capture.c
  ${CMAKE_CURRENT_SOURCE_DIR}/print_stream_mem.c

  # tshark sources
  ${CMAKE_CURRENT_SOURCE_DIR}/frame_tvbuff.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cfile.c
)

# FIXME: make this an option
IF(1)
    set(src ${src}
      ${CMAKE_CURRENT_SOURCE_DIR}/online_capture.c

      # tshark sources
      ${CMAKE_CURRENT_SOURCE_DIR}/tshark-capture.c
      ${CMAKE_CURRENT_SOURCE_DIR}/extcap.c
      ${CMAKE_CURRENT_SOURCE_DIR}/extcap_parser.c
      ${CMAKE_CURRENT_SOURCE_DIR}/extcap_spawn.c
      ${CMAKE_CURRENT_SOURCE_DIR}/capture_opts.c
      ${CMAKE_CURRENT_SOURCE_DIR}/filter_files.c
      ${CMAKE_CURRENT_SOURCE_DIR}/iface_toolbar.c
      ${CMAKE_CURRENT_SOURCE_DIR}/sync_pipe_write.c
    )

    set(header
      ${CMAKE_CURRENT_SOURCE_DIR}/frame_tvbuff.h
      ${CMAKE_CURRENT_SOURCE_DIR}/ws_dissect.h
      ${CMAKE_CURRENT_SOURCE_DIR}/ws_capture.h
      ${CMAKE_CURRENT_SOURCE_DIR}/cfile.h
    )
ENDIF()

add_definitions(
    -DHAVE_EXTCAP=1
    -DHAVE_LIBPCAP=1
    -DWITH_ONLINE_CAPTURE=1
)

if(WIN32)
  add_definitions( -DWS_NORETURN= )
else(WIN32)
  add_definitions( -DWS_NORETURN=_Noreturn )
endif(WIN32)

add_subdirectory(capchild)
add_subdirectory(caputils)

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

target_link_libraries(${PROJECT_NAME}
  PUBLIC
    ${Wireshark_LIBRARY}
    wiretap
    wsutil
    ${GLIB2_LIBRARIES}
    ${PCAP_LIBRARY}

  PRIVATE
    capchild
    caputils
)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            "-framework CoreFoundation"
            "-framework SystemConfiguration"
    )
endif()

if( ENABLE_EXAMPLES )

  # examples
  # 0
  file(GLOB simple_print_src examples/00-simple-print.c)
  add_executable(simple_print ${simple_print_src})
  target_compile_options(simple_print PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(simple_print ${PROJECT_NAME} ${GLIB2_LIBRARIES})
  add_test(simple_print simple_print "-t text" "${CMAKE_CURRENT_LIST_DIR}/samples/1-EPL-Frame.pcapng")

  # 1
  file(GLOB seek_offline_src examples/01-seek-interactive-offline.c)
  add_executable(seek_offline ${seek_offline_src})
  target_compile_options(seek_offline PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(seek_offline ${PROJECT_NAME} ${GLIB2_LIBRARIES})
  
  # 2
  file(GLOB seek_online_src examples/02-seek-interactive-online.c)
  MESSAGE(STATUS ${seek_online_src})
  add_executable(seek_online ${seek_online_src})
  target_compile_options(seek_online PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(seek_online ${PROJECT_NAME} ${GLIB2_LIBRARIES})

  #4
  file(GLOB multiple_print_src examples/04-open-multiple-files.c)
  add_executable(multiple_print ${multiple_print_src})
  target_compile_options(multiple_print PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(multiple_print ${PROJECT_NAME} ${GLIB2_LIBRARIES})
  #5
  file(GLOB load_plugin_src examples/05-load-plugin.c)
  add_executable(load_plugin ${load_plugin_src})
  target_compile_options(load_plugin PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(load_plugin ${PROJECT_NAME} ${GLIB2_LIBRARIES})
  #6
  file(GLOB stdin_open_src examples/06-stdin-open.c)
  add_executable(stdin_open ${stdin_open_src})
  target_compile_options(stdin_open PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(stdin_open ${PROJECT_NAME} ${GLIB2_LIBRARIES})
  #7
  file(GLOB file_types_src examples/07-file-types.c)
  add_executable(file_types ${file_types_src})
  target_compile_options(file_types PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(file_types ${PROJECT_NAME} ${GLIB2_LIBRARIES})
  #8
  file(GLOB uat_src examples/08-use-uat.c)
  add_executable(uat ${uat_src})
  target_compile_options(uat PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(uat ${PROJECT_NAME} ${GLIB2_LIBRARIES})
  #9
  file(GLOB online_src examples/09-online-print.c)
  add_executable(online ${online_src})
  target_compile_options(online PUBLIC ${GLIB2_CFLAGS_OTHER})
  target_link_libraries(online ${PROJECT_NAME} ${GLIB2_LIBRARIES})

  set( EXAMPLE_INSTALL_TARGETS simple_print seek_offline seek_online multiple_print load_plugin
      stdin_open
      file_types )

endif( ENABLE_EXAMPLES )

# install
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake"
    VERSION       ${CM_VERSION_MAJOR}.${CM_VERSION_MINOR}.${CM_VERSION_SUBMINOR}
    COMPATIBILITY SameMajorVersion
)

install( TARGETS ${PROJECT_NAME} ${PROJECT_NAME}_static ${EXAMPLE_INSTALL_TARGETS}
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

