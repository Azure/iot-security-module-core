

cmake_minimum_required(VERSION 3.15)

if (${run_unittests})
    add_definitions(
        # Collector Definitions
        -DCOLLECTOR_LISTENING_PORTS_ENABLED
        -DCOLLECTOR_SYSTEM_INFORMATION_ENABLED
        -DCOLLECTOR_CONNECTION_CREATE_ENABLED
        -DCOLLECTOR_HEARTBEAT_ENABLED
    )

    include_directories(
        mocks/inc
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/inc
    )

    add_subdirectory(core_int)
    add_subdirectory(core_ut)
    add_subdirectory(collector_collection_internal_ut)
    add_subdirectory(collector_collection_ut)
    add_subdirectory(collector_heartbeat_ut)
    add_subdirectory(collectors_info_ut)
    add_subdirectory(collector_ut)
    add_subdirectory(linked_list_ut)
    add_subdirectory(model/event_ut)
    add_subdirectory(model/message_ut)
    add_subdirectory(object_pool_ut)
    add_subdirectory(stack_ut)
    add_subdirectory(utils/collection/hashset_ut)
    add_subdirectory(utils/string_utils_ut)
    add_subdirectory(utils/notifier_ut)
endif()
