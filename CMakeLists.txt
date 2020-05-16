cmake_minimum_required(VERSION 3.15)

if(${WIN32})
    if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "")
    elseif(DEFINED ENV{VCPKG_INSTALLATION_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_INSTALLATION_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "")
    endif()
endif()

if(DEFINED ENV{VCPKG_DEFAULT_TRIPLET} AND NOT DEFINED VCPKG_TARGET_TRIPLET)
  set(VCPKG_TARGET_TRIPLET "$ENV{VCPKG_DEFAULT_TRIPLET}" CACHE STRING "")
endif()

set(TARGET_NAME "asc_security_core")
project(${TARGET_NAME})


FILE(READ ${CMAKE_CURRENT_LIST_DIR}/version.txt asc_security_core_VERSION)

# Include the common build rules for the security module core
include(cmake-modules/asc_security_core_build_rules.cmake)

set(GENERIC_LIB_VERSION ${asc_security_core_VERSION})
string(SUBSTRING ${asc_security_core_VERSION} 0 1 GENERIC_LIB_SOVERSION)

#the following variables are project-wide and can be used with cmake-gui
option(run_unittests "set run_unittests to ON to run unittests (default is OFF)" OFF)
option(run_coverage "set run_coverage to ON to gather coverage info (default is OFF)" OFF)
option(use_external_dependencies "set use_external_dependencies to ON if you're building this inside another project and intend to supply all dependencies externally" OFF)
option(use_installed_dependencies "set use_installed_dependencies to ON to use installed packages instead of building dependencies from submodules" OFF)
option(use_object_pool "use the predefined object pool instead of using heap memory" OFF)

# reslove logger log level
set(LOG_LEVELS NOTSET DEBUG INFO WARNING ERROR FATAL)
set(log_level NOTSET CACHE STRING "log_level: ${log_level} (default is NOTSET)")
set_property(CACHE log_level PROPERTY STRINGS NOTSET DEBUG INFO WARNING ERROR FATAL)
list(FIND LOG_LEVELS ${log_level} log_level_index)
if(log_level_index EQUAL -1)
    message(FATAL_ERROR "log_level must be one of ${LOG_LEVELS}")
else()
    add_definitions(-DLOG_LEVEL=${log_level_index})
endif()

if(${use_object_pool})
    add_definitions(-DUSE_OBJECT_POOL)
endif()

if(${run_unittests})
    add_definitions(
        # Collector Definitions
        -DCOLLECTOR_LISTENING_PORTS_ENABLED
        -DCOLLECTOR_SYSTEM_INFORMATION_ENABLED
        -DCOLLECTOR_CONNECTION_CREATE_ENABLED
        -DCOLLECTOR_HEARTBEAT_ENABLED
    )
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules")

if(NOT use_external_dependencies)
    #do not add or build any tests of the dependencies
    set(original_run_int_tests ${run_int_tests})
    set(original_run_unittests ${run_unittests})

    set(run_int_tests OFF)
    set(run_unittests OFF)

    if(NOT ${use_installed_dependencies})

    endif()

    set(run_int_tests ${original_run_int_tests})
    set(run_unittests ${original_run_unittests})
endif()

if (${run_unittests} AND ${run_coverage})
    include(asc_security_coreCheckAndIncludeCodeCov)
endif ()

set(workingDirectory "./")

add_definitions(
    -DCOLLECTOR_HEARTBEAT_ENABLED
)

#these are the C source files
set(source_c_files
    ${workingDirectory}/src/core.c
    ${workingDirectory}/src/collector_collection.c
    ${workingDirectory}/src/collector_collection_factory.c
    ${workingDirectory}/src/collector_collection_internal.c
    ${workingDirectory}/src/collectors_information.c
    ${workingDirectory}/src/collectors/heartbeat.c
    ${workingDirectory}/src/logger.c
    ${workingDirectory}/src/message_schema_consts.c
    ${workingDirectory}/src/model/collector.c
    ${workingDirectory}/src/model/event.c
    ${workingDirectory}/src/model/message/message_v10.c
    ${workingDirectory}/src/model/schema/schema_connection_create.c
    ${workingDirectory}/src/model/schema/schema_listening_ports.c
    ${workingDirectory}/src/model/schema/schema_heartbeat.c
    ${workingDirectory}/src/model/schema/schema_system_information.c
    ${workingDirectory}/src/utils/notifier.c
    ${workingDirectory}/src/utils/string_utils.c

    # asc folder
    ${workingDirectory}/src/asc/asc_json_builder.c
    ${workingDirectory}/src/asc/asc_json_parser.c
    ${workingDirectory}/src/asc/asc_json_pointer.c
    ${workingDirectory}/src/asc/asc_json_string.c
    ${workingDirectory}/src/asc/asc_json_token.c
    ${workingDirectory}/src/asc/asc_span.c
)

#these are the C headers
set(source_h_files
    ${workingDirectory}/inc/asc_security_core/core.h
    ${workingDirectory}/inc/asc_security_core/collector_collection.h
    ${workingDirectory}/inc/asc_security_core/collector_collection_factory.h
    ${workingDirectory}/inc/asc_security_core/collector_collection_internal.h
    ${workingDirectory}/inc/asc_security_core/collectors/connection_create.h
    ${workingDirectory}/inc/asc_security_core/collectors/heartbeat.h
    ${workingDirectory}/inc/asc_security_core/collectors/listening_ports.h
    ${workingDirectory}/inc/asc_security_core/collectors/system_information.h
    ${workingDirectory}/inc/asc_security_core/configuration.h
    ${workingDirectory}/inc/asc_security_core/iotsecurity_result.h
    ${workingDirectory}/inc/asc_security_core/message_schema_consts.h
    ${workingDirectory}/inc/asc_security_core/model/collector.h
    ${workingDirectory}/inc/asc_security_core/model/event.h
    ${workingDirectory}/inc/asc_security_core/model/message.h
    ${workingDirectory}/inc/asc_security_core/model/schema/schema_connection_create.h
    ${workingDirectory}/inc/asc_security_core/model/schema/schema_listening_ports.h
    ${workingDirectory}/inc/asc_security_core/model/schema/schema_system_information.h
    ${workingDirectory}/inc/asc_security_core/model/schema/schema_heartbeat.h
    ${workingDirectory}/inc/asc_security_core/model/schema/schemas.h
    ${workingDirectory}/inc/asc_security_core/utils/irand.h
    ${workingDirectory}/inc/asc_security_core/utils/itime.h
    ${workingDirectory}/inc/asc_security_core/utils/iuuid.h
    ${workingDirectory}/inc/asc_security_core/utils/network_utils.h
    ${workingDirectory}/inc/asc_security_core/utils/os_utils.h
    ${workingDirectory}/inc/asc_security_core/utils/string_utils.h

    # asc folder
    ${workingDirectory}/inc/asc_security_core/asc/_asc_cfg_prefix.h
    ${workingDirectory}/inc/asc_security_core/asc/_asc_cfg_suffix.h
    ${workingDirectory}/inc/asc_security_core/asc/_asc_cfg.h
    ${workingDirectory}/inc/asc_security_core/asc/asc_hex_private.h
    ${workingDirectory}/inc/asc_security_core/asc/asc_json_string_private.h
    ${workingDirectory}/inc/asc_security_core/asc/asc_json.h
    ${workingDirectory}/inc/asc_security_core/asc/asc_precondition_internal.h
    ${workingDirectory}/inc/asc_security_core/asc/asc_precondition.h
    ${workingDirectory}/inc/asc_security_core/asc/asc_result.h
    ${workingDirectory}/inc/asc_security_core/asc/asc_span_private.h
    ${workingDirectory}/inc/asc_security_core/asc/asc_span.h

    # logger
    ${workingDirectory}/inc/asc_security_core/logger.h
)

#the following "set" statetement exports across the project a global variable called COMMON_INC_FOLDER that expands to whatever needs to included when using COMMON library
set(ASC_SECURITY_CORE_INC_FOLDER ${CMAKE_CURRENT_LIST_DIR}/inc CACHE INTERNAL "this is what needs to be included if using sharedLib lib" FORCE)
set(ASC_SECURITY_CORE_SRC_FOLDER ${CMAKE_CURRENT_LIST_DIR}/src CACHE INTERNAL "this is what needs to be included when doing include sources" FORCE)

include_directories(
    ${ASC_SECURITY_CORE_INC_FOLDER}
)

get_directory_property(hasParent PARENT_DIRECTORY)
if (hasParent)
    set(asc_security_core_BUILT "6d0045c0-15e0-11ea-b6f7-7f262b22f74d" PARENT_SCOPE)
endif ()

add_library(asc_security_core
    ${source_c_files}
    ${source_h_files}
)

set(install_targets
    asc_security_core
)

if (use_external_dependencies)
    include_directories(
        # Whenever use_external_dependencies == ON we need to provide the path to the dependecies include directories
        # Currently it means the path to azure-sdk-for-c/sdk/core/core/inc
        ${external_dependencies_include}
    )
else()
    target_link_libraries(asc_security_core
    )

    set(install_targets
        ${install_targets}
    )
endif()

if (NOT WIN32)
    set_target_properties(asc_security_core
        PROPERTIES
        VERSION ${GENERIC_LIB_VERSION}
        SOVERSION ${GENERIC_LIB_SOVERSION}
    )
endif ()

# Set CMAKE_INSTALL_LIBDIR if not defined
include(GNUInstallDirs)

# Install asc_security_core
set(package_location "cmake")

if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

install(TARGETS ${install_targets} EXPORT asc_security_coreTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/../bin
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(FILES ${source_h_files} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/asc_security_core)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${asc_security_core_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_file("cmake-modules/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}Config.cmake"
    COPYONLY
)

install(EXPORT asc_security_coreTargets
    FILE
        "${PROJECT_NAME}Targets.cmake"
    DESTINATION
        ${package_location}
)

install(
    FILES
        "cmake-modules/${PROJECT_NAME}Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION
        ${package_location}
)

if (${run_unittests})
    enable_testing()
    include(CTest)

    add_definitions(
        -DCOLLECTOR_TEST_ENABLED
        -DNOTIFIERS_POOL_ENTRIES=2
        -DCOLLECTOR_OBJECT_POOL_COUNT=6
    )

    add_subdirectory(tests)

    if (${run_coverage})
        include(asc_security_coreCreateCodeCoverageTargets)
    endif ()
endif ()

compileTargetAsC99(asc_security_core)
