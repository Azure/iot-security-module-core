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

#include <stdlib.h>

#include "../inc/collector_mock.h"
#include "asc_security_core/message_schema_consts.h"
#include "asc_security_core/model/event.h"
#include "asc_security_core/object_pool.h"
#include "asc_security_core/utils/itime.h"

#define COLLECTOR_INTERNAL_OBJECT_POOL_COUNT 6

OBJECT_POOL_DECLARATIONS(collector_state, COLLECTOR_INTERNAL_OBJECT_POOL_COUNT);

OBJECT_POOL_DEFINITIONS(collector_state, COLLECTOR_INTERNAL_OBJECT_POOL_COUNT);

IOTSECURITY_RESULT collector_mock_init_with_params(collector_internal_t* collector_internal_ptr, const char* name, COLLECTOR_TYPE type, COLLECTOR_PRIORITY priority) {
    if (collector_internal_ptr == NULL) {
        return IOTSECURITY_RESULT_BAD_ARGUMENT;
    }

    memset(collector_internal_ptr, 0, sizeof(*collector_internal_ptr));

    strcpy(collector_internal_ptr->name, name);
    collector_internal_ptr->type = type;
    collector_internal_ptr->priority = priority;

    collector_internal_ptr->collect_function = collector_mock_get_events;
    collector_internal_ptr->deinit_function = collector_mock_deinit;

    collector_state_handle collector_state = object_pool_get(collector_state);
    linked_list_event_t_init(&(collector_state->event_queue), event_deinit);
    collector_internal_ptr->state = collector_state;

    return IOTSECURITY_RESULT_OK;
}

IOTSECURITY_RESULT collector_mock_init(collector_internal_t* collector_internal_ptr) {
    return collector_mock_init_with_params(collector_internal_ptr, "Mock_ListeningPortsCollector", COLLECTOR_TYPE_TEST, COLLECTOR_PRIORITY_HIGH);
}

IOTSECURITY_RESULT collector_mock_get_events(collector_internal_t* collector_internal_ptr, linked_list_event_t_handle events) {
    if (collector_internal_ptr == NULL || events == NULL) {
        return IOTSECURITY_RESULT_BAD_ARGUMENT;
    }

    linked_list_event_t_handle internal_queue = &(((collector_state_handle)collector_internal_ptr->state)->event_queue);

    if (linked_list_event_t_get_size(internal_queue) == 0) {
        return IOTSECURITY_RESULT_OK;
    }

    while (linked_list_event_t_get_size(internal_queue) > 0) {
        event_t* event_ptr = linked_list_event_t_remove_first(internal_queue);

        // Break if the target list is full
        if (linked_list_event_t_add_last(events, event_ptr) == NULL) {
            break;
        }
    }

    return IOTSECURITY_RESULT_OK;
}

void collector_mock_deinit(collector_internal_t* collector_internal_ptr) {
    if (collector_internal_ptr == NULL) {
        return;
    }

    if (collector_internal_ptr->state != NULL) {
        linked_list_event_t_handle internal_queue = &(((collector_state_handle)collector_internal_ptr->state)->event_queue);
        linked_list_event_t_deinit(internal_queue);
        object_pool_free(collector_state, collector_internal_ptr->state);
    }

    memset(collector_internal_ptr, 0, sizeof(*collector_internal_ptr));
}

IOTSECURITY_RESULT collector_mock_add_event_to_queue(collector_internal_t* collector_internal_ptr, const char* event_name) {
    if (collector_internal_ptr == NULL || event_name == NULL) {
        return IOTSECURITY_RESULT_BAD_ARGUMENT;
    }

    event_t* event_ptr = event_init(LISTENING_PORTS_PAYLOAD_SCHEMA_VERSION, event_name, EVENT_PERIODIC_CATEGORY, EVENT_TYPE_SECURITY_VALUE, itime_time(NULL));
    if (event_ptr == NULL) {
        return IOTSECURITY_RESULT_EXCEPTION;
    }

    event_build(event_ptr);

    linked_list_event_t_handle internal_queue = &(((collector_state_handle)collector_internal_ptr->state)->event_queue);

    if (linked_list_event_t_add_last(internal_queue, event_ptr) == NULL) {
        return IOTSECURITY_RESULT_EXCEPTION;
    }

    return IOTSECURITY_RESULT_OK;
}