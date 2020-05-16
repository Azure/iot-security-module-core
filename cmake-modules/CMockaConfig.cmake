find_package(cmocka CONFIG REQUIRED)

enable_testing()
include(CTest)

function(ADD_TEST_CORE _TARGET_NAME)

    set(one_value_arguments
    )

    set(multi_value_arguments
        SOURCES
        COMPILE_OPTIONS
        MOCK_FUNCTIONS
        PRIVATE_ACCESS
        LINK_TARGETS
    )

    cmake_parse_arguments(_add_test_core
        ""
        "${one_value_arguments}"
        "${multi_value_arguments}"
        ${ARGN}
    )

    if (NOT DEFINED _add_test_core_SOURCES)
        message(FATAL_ERROR "No sources provided for target ${_TARGET_NAME}")
    endif()

    add_executable(${_TARGET_NAME} ${_add_test_core_SOURCES})

    if (DEFINED _add_test_core_COMPILE_OPTIONS)
        target_compile_options(${_TARGET_NAME}
            PRIVATE ${_add_test_core_COMPILE_OPTIONS}
        )
    endif()

    if (DEFINED _add_test_core_LINK_TARGETS)
        target_link_libraries(${_TARGET_NAME}
            PRIVATE ${CMOCKA_LIBRARIES} ${_add_test_core_LINK_TARGETS}
        )
    endif()

    if (DEFINED _add_test_core_MOCK_FUNCTIONS)
        set(functions "")
        foreach(function ${_add_test_core_MOCK_FUNCTIONS})
            set(functions "${functions} -Wl,--wrap=${function}")
        endforeach()

        set_target_properties(${_TARGET_NAME}
            PROPERTIES LINK_FLAGS
            ${functions}
        )
    endif()

    target_include_directories(${_TARGET_NAME} PRIVATE ${CMOCKA_INCLUDE_DIR})

    add_test(${_TARGET_NAME} ${TARGET_SYSTEM_EMULATOR} ${_TARGET_NAME})

endfunction (ADD_TEST_CORE)