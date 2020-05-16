/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/
#include <stdio.h>
#include <string.h>

#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "asc_security_core/core.h"

#include "../mocks/inc/collector_mock.h"
#include "../mocks/inc/collector_collection_factory.h"
#include "../mocks/inc/utils/itime.h"

const char* __wrap_os_utils_get_security_module_id();

const char* __wrap_os_utils_get_security_module_id() {
    return "machine-id";
}

static void core_int_mixed_priorities_round_robin(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    core_t* core_ptr = NULL;
    linked_list_security_message_t _local_message_list;
    linked_list_security_message_t* message_list_handle = &_local_message_list;
    linked_list_security_message_t_init(message_list_handle, object_pool_security_message_t_free);

    char expected[ASC_MESSAGE_MAX_SIZE] = "{"
        "\"AgentVersion\":\"0.0.1\","
        "\"AgentId\":\"machine-id\","
        "\"MessageSchemaVersion\":\"1.0\","
        "\"Events\":["
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h10\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h20\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h30\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h11\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h21\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h31\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h12\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h22\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"h32\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"m10\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"m20\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"m21\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l10\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l11\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l12\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l13\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l14\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l15\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l16\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l17\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l18\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "},"
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"l19\","
                "\"PayloadSchemaVersion\":\"1\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "}"
        "]"
    "}";

    // <number of events>/*name of the collector*/
    collector_collection_factory_init_test_data(3/*h1*/, 3/*h2*/, 3/*h3*/, 1/*m1*/, 2/*m2*/, 10/*l1*/);

    // act
    {
        core_ptr = core_init();
        assert_non_null(core_ptr);

        result = core_collect(core_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = core_get(core_ptr, message_list_handle);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        assert_int_equal(1, linked_list_security_message_t_get_size(message_list_handle));

        assert_string_equal(expected, linked_list_security_message_t_get_first(message_list_handle)->data);

        linked_list_security_message_t_deinit(message_list_handle);

        core_deinit(core_ptr);
    }
}

static int  core_int_setup(void** state) {
    mock_itime_reset();
    collector_collection_factory_init();
    return 0;
}

static int  core_int_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(core_int_mixed_priorities_round_robin, core_int_setup, core_int_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}