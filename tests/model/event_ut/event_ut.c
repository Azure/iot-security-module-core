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

#include "asc_security_core/model/event.h"

static void event_ut_init_with_invalid_args(void** state) {
    event_t* event_ptr = NULL;

    event_ptr = event_init(NULL, "name", "category", "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", NULL, "category", "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", "name", NULL, "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", "name", "category", NULL, 0);
    assert_null(event_ptr);

    event_ptr = event_init("", "name", "category", "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", "", "category", "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", "name", "", "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", "name", "category", "", 0);
    assert_null(event_ptr);

    event_ptr = event_init(" \t\n\r\f\v", "name", "category", "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", " \t\n\r\f\v", "category", "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", "name", " \t\n\r\f\v", "type", 0);
    assert_null(event_ptr);

    event_ptr = event_init("payload schema version", "name", "category", " \t\n\r\f\v", 0);
    assert_null(event_ptr);
}

static void event_ut_init_with_event(void** state) {
    event_t* event_ptr = NULL;

    event_ptr = event_init("dummy payload schema version", "dummy name", "dummy category", "dummy type", 0);
    assert_non_null(event_ptr);
    assert_true(asc_span_is_content_equal(asc_span_from_str("dummy name"), event_get_name(event_ptr)));
    assert_true(asc_span_is_content_equal(asc_span_from_str("dummy payload schema version"), event_get_payload_schema_version(event_ptr)));
    assert_true(asc_span_is_content_equal(asc_span_from_str("dummy category"), event_get_category(event_ptr)));
    assert_true(asc_span_is_content_equal(asc_span_from_str("dummy type"), event_get_type(event_ptr)));
    assert_int_equal(0, event_get_local_time(event_ptr));

    event_deinit(event_ptr);
    event_ptr = NULL;
}

static void event_ut_build_null(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    // act
    {
        result = event_build(NULL);
    }

    // assert
    {
        assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, result);
    }
}

static void event_ut_get_null(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    // act
    {
        result = event_get_data(NULL, NULL, 0);
    }

    // assert
    {
        assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, result);
    }
}

static void event_ut_get_data_from_event_ptr(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_EVENT_MAX_SIZE] = "{"
        "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
        "\"Name\":\"dummy name\","
        "\"PayloadSchemaVersion\":\"dummy payload schema version\","
        "\"Category\":\"dummy category\","
        "\"EventType\":\"dummy type\","
        "\"TimestampLocal\":\"2012-12-12T14:12:12\","
        "\"TimestampUTC\":\"2012-12-12T12:12:12\","
        "\"Payload\":[],"
        "\"IsEmpty\":true"
    "}";

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    event_t* event_ptr = NULL;

    // act
    {
        event_ptr = event_init("dummy payload schema version", "dummy name", "dummy category", "dummy type", 0);
        assert_non_null(event_ptr);

        result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_string_equal(expected, actual);
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;
    }
}

static void event_ut_get_data_from_event_ptr_after_build(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_EVENT_MAX_SIZE] = "{"
        "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
        "\"Name\":\"dummy name\","
        "\"PayloadSchemaVersion\":\"dummy payload schema version\","
        "\"Category\":\"dummy category\","
        "\"EventType\":\"dummy type\","
        "\"TimestampLocal\":\"2012-12-12T14:12:12\","
        "\"TimestampUTC\":\"2012-12-12T12:12:12\","
        "\"Payload\":[],"
        "\"IsEmpty\":true"
    "}";

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    event_t* event_ptr = NULL;

    // act
    {
        event_ptr = event_init("dummy payload schema version", "dummy name", "dummy category", "dummy type", 0);
        assert_non_null(event_ptr);

        result = event_build(event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_string_equal(expected, actual);
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;
    }
}

static void event_ut_get_data_multiple_times(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_EVENT_MAX_SIZE] = "{"
        "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
        "\"Name\":\"dummy name\","
        "\"PayloadSchemaVersion\":\"dummy payload schema version\","
        "\"Category\":\"dummy category\","
        "\"EventType\":\"dummy type\","
        "\"TimestampLocal\":\"2012-12-12T14:12:12\","
        "\"TimestampUTC\":\"2012-12-12T12:12:12\","
        "\"Payload\":[],"
        "\"IsEmpty\":true"
    "}";

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    event_t* event_ptr = NULL;

    // act
    {
        event_ptr = event_init("dummy payload schema version", "dummy name", "dummy category", "dummy type", 0);
        assert_non_null(event_ptr);

        for (int i = 0; i < 10; i++) {
            result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
            assert_int_equal(IOTSECURITY_RESULT_OK, result);
        }
    }

    // assert
    {
        assert_string_equal(expected, actual);
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;
    }
}

static void event_ut_get_get_length_null(void** state) {
    event_t* event_ptr = NULL;
    assert_int_equal(0, event_get_length(event_ptr));
}

static void event_ut_populate_extra_details(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_EVENT_MAX_SIZE] = "{"
        "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
        "\"Name\":\"SystemInformation\","
        "\"PayloadSchemaVersion\":\"1.0\","
        "\"Category\":\"Periodic\","
        "\"EventType\":\"Operational\","
        "\"TimestampLocal\":\"2012-12-12T14:12:12\","
        "\"TimestampUTC\":\"2012-12-12T12:12:12\","
        "\"Payload\":["
            "{"
                "\"OSName\":\"os_name\","
                "\"OSVersion\":\"os_version\","
                "\"OsArchitecture\":\"os_architecture\","
                "\"HostName\":\"hostname\","
                "\"TotalPhysicalMemoryInKB\":100,"
                "\"FreePhysicalMemoryInKB\":55,"
                "\"ExtraDetails\":{"
                    "\"a\":\"1\","
                    "\"b\":\"true\","
                    "\"c\":\"C\""
                "}"
            "}"
        "],"
        "\"IsEmpty\":false"
    "}";

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };
    event_t* event_ptr = NULL;

    event_ptr = event_init("1.0", "SystemInformation", "Periodic", "Operational", 0);
    assert_non_null(event_ptr);

    system_information_t* event_data = schema_system_information_init();
    assert_non_null(event_data);

    result = schema_system_information_set_os_name(event_data, "os_name");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_os_version(event_data, "os_version");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_os_architecture(event_data, "os_architecture");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_hostname(event_data, "hostname");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_memory_total_physical_in_kb(event_data, 100);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_memory_free_physical_in_kb(event_data, 55);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    asc_pair extra_details[SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES] = {
        asc_pair_from_str("a", "1"),
        asc_pair_from_str("b", "true"),
        asc_pair_from_str("c", "C"),
    };

    result = schema_system_information_set_extra_details(event_data, extra_details);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    // act
    {
        result = event_append_system_information(event_ptr, event_data);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_build(event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_true(asc_span_is_content_equal(asc_span_from_str("SystemInformation"), event_get_name(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("1.0"), event_get_payload_schema_version(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Periodic"), event_get_category(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Operational"), event_get_type(event_ptr)));
        assert_int_equal(0, event_get_local_time(event_ptr));
        assert_string_equal(expected, actual);
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;

        schema_system_information_deinit(event_data);
        event_data = NULL;
    }
}

static void event_ut_append_system_information(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_EVENT_MAX_SIZE] = "{"
        "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
        "\"Name\":\"SystemInformation\","
        "\"PayloadSchemaVersion\":\"1.0\","
        "\"Category\":\"Periodic\","
        "\"EventType\":\"Operational\","
        "\"TimestampLocal\":\"2012-12-12T14:12:12\","
        "\"TimestampUTC\":\"2012-12-12T12:12:12\","
        "\"Payload\":["
            "{"
                "\"OSName\":\"os_name\","
                "\"OSVersion\":\"os_version\","
                "\"OsArchitecture\":\"os_architecture\","
                "\"HostName\":\"hostname\","
                "\"TotalPhysicalMemoryInKB\":100,"
                "\"FreePhysicalMemoryInKB\":55"
            "}"
        "],"
        "\"IsEmpty\":false"
    "}";

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };
    event_t* event_ptr = NULL;

    event_ptr = event_init("1.0", "SystemInformation", "Periodic", "Operational", 0);
    assert_non_null(event_ptr);

    system_information_t* event_data = schema_system_information_init();
    assert_non_null(event_data);

    result = schema_system_information_set_os_name(event_data, "os_name");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_os_version(event_data, "os_version");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_os_architecture(event_data, "os_architecture");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_hostname(event_data, "hostname");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_memory_total_physical_in_kb(event_data, 100);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_system_information_set_memory_free_physical_in_kb(event_data, 55);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    // act
    {
        result = event_append_system_information(event_ptr, event_data);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_build(event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_true(asc_span_is_content_equal(asc_span_from_str("SystemInformation"), event_get_name(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("1.0"), event_get_payload_schema_version(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Periodic"), event_get_category(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Operational"), event_get_type(event_ptr)));
        assert_int_equal(0, event_get_local_time(event_ptr));
        assert_string_equal(expected, actual);
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;

        schema_system_information_deinit(event_data);
        event_data = NULL;
    }
}

static void event_ut_append_connection_create(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_EVENT_MAX_SIZE] = "{"
        "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
        "\"Name\":\"ConnectionCreate\","
        "\"PayloadSchemaVersion\":\"1.0\","
        "\"Category\":\"Aggregated\","
        "\"EventType\":\"Security\","
        "\"TimestampLocal\":\"2012-12-12T14:12:12\","
        "\"TimestampUTC\":\"2012-12-12T12:12:12\","
        "\"Payload\":["
            "{"
                "\"LocalAddress\":\"1.2.3.4\","
                "\"RemoteAddress\":\"5.6.7.8\","
                "\"Protocol\":\"TCP\","
                "\"LocalPort\":\"1111\","
                "\"RemotePort\":\"2222\","
                "\"Direction\":\"In\""
            "},"
            "{"
                "\"LocalAddress\":\"1.2.3.4\","
                "\"RemoteAddress\":\"5.6.7.8\","
                "\"Protocol\":\"TCP\","
                "\"LocalPort\":\"1111\","
                "\"RemotePort\":\"2222\","
                "\"Direction\":\"Out\""
            "}"
        "],"
        "\"IsEmpty\":false"
    "}";

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    event_t* event_ptr = NULL;

    event_ptr = event_init("1.0", "ConnectionCreate", "Aggregated", "Security", 0);
    assert_non_null(event_ptr);

    connection_create_t* event_data = schema_connection_create_init();
    assert_non_null(event_data);

    result = schema_connection_create_set_network_protocol(event_data, NETWORK_PROTOCOL_IPV4);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_connection_create_set_transport_protocol(event_data, TRANSPORT_PROTOCOL_TCP);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_connection_create_set_bytes_in(event_data, 1000);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_connection_create_set_bytes_out(event_data, 1000);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    uint32_t local_ipv4 = 0;
    assert_true(network_utils_inet_pton(NETWORK_PROTOCOL_IPV4, "1.2.3.4", &local_ipv4));

    result = schema_connection_create_set_local_ipv4(event_data, local_ipv4);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_connection_create_set_local_port(event_data, 1111);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    uint32_t remote_ipv4 = 0;
    assert_true(network_utils_inet_pton(NETWORK_PROTOCOL_IPV4, "5.6.7.8", &remote_ipv4));

    result = schema_connection_create_set_remote_ipv4(event_data, remote_ipv4);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_connection_create_set_remote_port(event_data, 2222);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    // act
    {
        result = event_append_connection_create(event_ptr, event_data);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_build(event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_true(asc_span_is_content_equal(asc_span_from_str("ConnectionCreate"), event_get_name(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("1.0"), event_get_payload_schema_version(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Aggregated"), event_get_category(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Security"), event_get_type(event_ptr)));
        assert_int_equal(0, event_get_local_time(event_ptr));
        assert_string_equal(expected, actual);
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;

        schema_connection_create_deinit(event_data);
        event_data = NULL;
    }
}

static void event_ut_append_listening_ports(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_EVENT_MAX_SIZE] = "{"
        "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
        "\"Name\":\"ListeningPorts\","
        "\"PayloadSchemaVersion\":\"1.0\","
        "\"Category\":\"Periodic\","
        "\"EventType\":\"Security\","
        "\"TimestampLocal\":\"2012-12-12T14:12:12\","
        "\"TimestampUTC\":\"2012-12-12T12:12:12\","
        "\"Payload\":["
            "{"
                "\"Protocol\":\"tcp\","
                "\"LocalAddress\":\"127.0.0.1\","
                "\"LocalPort\":\"43399\","
                "\"RemoteAddress\":\"0.0.0.0\","
                "\"RemotePort\":\"*\","
                "\"ExtraDetails\":{"
                    "\"State\":\"10\","
                    "\"Recv-Q\":\"0\","
                    "\"Send-Q\":\"0\""
                "}"
            "}"
        "],"
        "\"IsEmpty\":false"
    "}";

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    event_t* event_ptr = NULL;

    event_ptr = event_init("1.0", "ListeningPorts", "Periodic", "Security", 0);
    assert_non_null(event_ptr);

    listening_ports_t* event_data = schema_listening_ports_init();
    assert_non_null(event_data);

    result = schema_listening_ports_set_protocol(event_data, "tcp");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_listening_ports_set_local_address(event_data, "127.0.0.1");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_listening_ports_set_local_port(event_data, "43399");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_listening_ports_set_remote_address(event_data, "0.0.0.0");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = schema_listening_ports_set_remote_port(event_data, "*");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    asc_pair extra_details[SCHEMA_LISTENING_PORTS_EXTRA_DETAILS_ENTRIES] = {
        asc_pair_from_str("State", "10"),
        asc_pair_from_str("Recv-Q", "0"),
        asc_pair_from_str("Send-Q", "0")
    };
    result = schema_listening_ports_set_extra_details(event_data, extra_details);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    // act
    {
        result = event_append_listening_ports(event_ptr, event_data);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_build(event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_true(asc_span_is_content_equal(asc_span_from_str("ListeningPorts"), event_get_name(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("1.0"), event_get_payload_schema_version(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Periodic"), event_get_category(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Security"), event_get_type(event_ptr)));
        assert_int_equal(0, event_get_local_time(event_ptr));
        assert_string_equal(expected, actual);
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;

        schema_listening_ports_deinit(event_data);
        event_data = NULL;
    }
}

static void event_ut_append_listening_ports_null(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_EVENT_MAX_SIZE] = "{"
        "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
        "\"Name\":\"ListeningPorts\","
        "\"PayloadSchemaVersion\":\"1.0\","
        "\"Category\":\"Periodic\","
        "\"EventType\":\"Security\","
        "\"TimestampLocal\":\"2012-12-12T14:12:12\","
        "\"TimestampUTC\":\"2012-12-12T12:12:12\","
        "\"Payload\":[],"
        "\"IsEmpty\":true"
    "}";

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    event_t* event_ptr = NULL;

    event_ptr = event_init("1.0", "ListeningPorts", "Periodic", "Security", 0);
    assert_non_null(event_ptr);

    // act
    {
        result = event_append_listening_ports(event_ptr, NULL);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_build(event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_true(asc_span_is_content_equal(asc_span_from_str("ListeningPorts"), event_get_name(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("1.0"), event_get_payload_schema_version(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Periodic"), event_get_category(event_ptr)));
        assert_true(asc_span_is_content_equal(asc_span_from_str("Security"), event_get_type(event_ptr)));
        assert_int_equal(0, event_get_local_time(event_ptr));
        assert_string_equal(expected, actual);
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;
    }
}

static int event_ut_setup(void** state) {
    return 0;
}

static int event_ut_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(event_ut_init_with_invalid_args, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_init_with_event, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_build_null, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_get_null, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_get_data_from_event_ptr, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_get_data_from_event_ptr_after_build, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_get_data_multiple_times, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_get_get_length_null, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_populate_extra_details, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_append_system_information, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_append_connection_create, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_append_listening_ports, event_ut_setup, event_ut_teardown),
    cmocka_unit_test_setup_teardown(event_ut_append_listening_ports_null, event_ut_setup, event_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}