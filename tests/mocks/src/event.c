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
#include "asc_security_core/asc/asc_span.h"
#include "asc_security_core/model/event.h"

#define TEST_MAX_LEN 20

typedef struct event {
    COLLECTION_INTERFACE(struct event);

    char data[TEST_MAX_LEN];
} event_t;

event_t* __wrap_event_init(const char* payload_schema_version, const char* name, const char* category, const char* event_type, time_t local_time);
void __wrap_event_deinit(event_t* event_ptr);
IOTSECURITY_RESULT __wrap_event_get_data(event_t* event_ptr, char* buffer, size_t size);
IOTSECURITY_RESULT __wrap_event_build(event_t* event_ptr);

event_t* __wrap_event_init(const char* payload_schema_version, const char* name, const char* category, const char* event_type, time_t local_time) {
    event_t* event_ptr = object_pool_get(event_t);
    if (event_ptr == NULL) {
        return NULL;
    }

    memset(event_ptr, 0, sizeof(event_t));
    memcpy(event_ptr->data, name, strlen(name));
    return event_ptr;
}

void __wrap_event_deinit(event_t* event_ptr) {
    if (event_ptr != NULL) {
        object_pool_free(event_t, event_ptr);
        event_ptr = NULL;
    }
}

IOTSECURITY_RESULT __wrap_event_get_data(event_t* event_ptr, char* buffer, size_t size) {
    snprintf(buffer, size, "%s", event_ptr->data);
    return IOTSECURITY_RESULT_OK;
}

IOTSECURITY_RESULT __wrap_event_build(event_t* event_ptr) {
    return IOTSECURITY_RESULT_OK;
}