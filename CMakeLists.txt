cmake_minimum_required (VERSION 2.6)
project (wping C)
set (Tutorial_VERSION_MAJOR 0)
set (Tutorial_VERSION_MINOR 1)
add_subdirectory( "${PROJECT_SOURCE_DIR}/3rdparty/jansson" )

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/WPingConfig.h.in"
  "${PROJECT_BINARY_DIR}/WPingConfig.h"
  )

# os specific libs
FUNCTION(TARGET_OS_LIBRARIES target)
	IF(WIN32)
		TARGET_LINK_LIBRARIES(${target} ws2_32)
	ELSEIF(CMAKE_SYSTEM_NAME MATCHES "(Solaris|SunOS)")
		TARGET_LINK_LIBRARIES(${target} socket nsl)
	ELSEIF(CMAKE_SYSTEM_NAME MATCHES "(AIX)")
		TARGET_LINK_LIBRARIES(${target} m)
	ENDIF ()
ENDFUNCTION()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_CONFIG_H")

IF(CMAKE_BUILD_TYPE MATCHES Debug)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEBUG")
ENDIF(CMAKE_BUILD_TYPE MATCHES Debug)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}")
find_package(C99 REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C99_C_FLAGS}")
 
find_package (Threads)
add_executable(wping wping.c 3rdparty/mongoose/mongoose.c)
target_link_libraries (wping ${CMAKE_THREAD_LIBS_INIT})
TARGET_LINK_LIBRARIES(wping jansson)
target_os_libraries(wping)

#set( CMAKE_VERBOSE_MAKEFILE on )

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_BINARY_DIR}/3rdparty/jansson/include")
include_directories("${PROJECT_SOURCE_DIR}/3rdparty/mongoose")
