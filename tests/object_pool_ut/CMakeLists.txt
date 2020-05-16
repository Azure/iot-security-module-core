cmake_minimum_required (VERSION 3.10)
set(TARGET_NAME "object_pool_ut")

project (${TARGET_NAME} LANGUAGES C)

set(CMAKE_C_STANDARD 99)

include(CMockaConfig)

set(mocksWorkingDirectory "..")

set(MOCK_FUNCTIONS
)

add_test_core(${TARGET_NAME} SOURCES
                object_pool_ut.c
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                MOCK_FUNCTIONS ${MOCK_FUNCTIONS}
                LINK_TARGETS asc_security_core
                )