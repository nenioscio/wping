cmake_minimum_required (VERSION 2.6)
project (wping C)
set (Tutorial_VERSION_MAJOR 0)
set (Tutorial_VERSION_MINOR 1)

set(JANSSON_BUILD_DOCS CACHE INTERNAL NO FORCE)
set (JANSSON_BUNDLED_DIR "${PROJECT_SOURCE_DIR}/3rdparty/jansson")
add_subdirectory( ${JANSSON_BUNDLED_DIR} EXCLUDE_FROM_ALL )

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/WPingConfig.h.in"
  "${PROJECT_BINARY_DIR}/WPingConfig.h"
  )

# os specific libs
function(TARGET_OS_LIBRARIES target)
	if(WIN32)
		target_link_libraries(${target} ws2_32)
	elseif(CMAKE_SYSTEM_NAME MATCHES "(Solaris|SunOS)")
		target_link_libraries(${target} socket nsl)
	elseif(CMAKE_SYSTEM_NAME MATCHES "(AIX)")
		target_link_libraries(${target} m)
	endif ()
endfunction()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_CONFIG_H")

if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEBUG")
endif(CMAKE_BUILD_TYPE MATCHES Debug)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}")
find_package(C99 REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C99_C_FLAGS}")
 
find_package (Threads)
add_executable(wping wping.c 3rdparty/mongoose/mongoose.c)
target_link_libraries(wping ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(wping jansson)
TARGET_OS_LIBRARIES(wping)

#set( CMAKE_VERBOSE_MAKEFILE on )

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}")
include_directories("${PROJECT_BINARY_DIR}/3rdparty/jansson/include")
include_directories("${PROJECT_SOURCE_DIR}/3rdparty/mongoose")

install(TARGETS wping RUNTIME DESTINATION bin)

set(CPACK_PACKAGE_NAME "wping")
set(CPACK_PACKAGE_VENDOR "EGB")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/postin.sh")
include(CPack)
