cmake_minimum_required (VERSION 3.10)
set(TARGET_NAME "message_ut")

project (${TARGET_NAME} LANGUAGES C)

set(CMAKE_C_STANDARD 99)

include(CMockaConfig)

set(mocksWorkingDirectory "../..")

set(MOCK_FUNCTIONS
    itime_time
    itime_utcnow
    itime_localtime
    itime_iso8601
    itime_difftime
    iuuid_generate
)

add_test_core(${TARGET_NAME} SOURCES
    message_ut.c
    ${mocksWorkingDirectory}/mocks/src/utils/iuuid.c
    ${mocksWorkingDirectory}/mocks/src/utils/itime.c
    ${mocksWorkingDirectory}/mocks/src/network_utils.c
    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
    MOCK_FUNCTIONS ${MOCK_FUNCTIONS}
    LINK_TARGETS asc_security_core
)
