cmake_minimum_required (VERSION 3.10)
set(TARGET_NAME "notifier_ut")

project (${TARGET_NAME} LANGUAGES C)

set(CMAKE_C_STANDARD 99)

include(CMockaConfig)

add_test_core(${TARGET_NAME} SOURCES
                notifier_ut.c
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                LINK_TARGETS asc_security_core
                )
