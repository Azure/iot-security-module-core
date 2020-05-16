cmake_minimum_required (VERSION 3.10)
set(TARGET_NAME "core_int")

project (${TARGET_NAME} LANGUAGES C)

set(CMAKE_C_STANDARD 99)

include(CMockaConfig)

set(mocksWorkingDirectory "..")

set(MOCK_FUNCTIONS
    irand_int
    itime_difftime
    itime_iso8601
    itime_localtime
    itime_time
    itime_utcnow
    iuuid_generate
    collector_collection_internal_init_startup_time
    collector_collection_factory_get_initialization_array
    os_utils_get_security_module_id
)

add_test_core(${TARGET_NAME} SOURCES
    core_int.c
    ${mocksWorkingDirectory}/mocks/src/event.c
    ${mocksWorkingDirectory}/mocks/src/collector_collection_factory.c
    ${mocksWorkingDirectory}/mocks/src/collector_mock.c
    ${mocksWorkingDirectory}/mocks/src/utils/irand.c
    ${mocksWorkingDirectory}/mocks/src/utils/itime.c
    ${mocksWorkingDirectory}/mocks/src/utils/iuuid.c
    ${mocksWorkingDirectory}/mocks/src/network_utils.c
    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
    MOCK_FUNCTIONS ${MOCK_FUNCTIONS}
    LINK_TARGETS asc_security_core
)
