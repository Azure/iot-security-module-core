#include <stdio.h>
#include "../inc/collector_collection_factory.h"
#include "../inc/collector_mock.h"
#include "asc_security_core/model/event.h"

IOTSECURITY_RESULT __wrap_collector_collection_factory_get_initialization_array(INIT_FUNCTION** init_array, uint32_t* init_array_size);
IOTSECURITY_RESULT __wrap_collector_collection_internal_init_startup_time(collector_collection_t* collector_collection_ptr);

static IOTSECURITY_RESULT _collector_collection_init_h1(collector_internal_t* collector_internal_ptr);
static IOTSECURITY_RESULT _collector_collection_init_h2(collector_internal_t* collector_internal_ptr);
static IOTSECURITY_RESULT _collector_collection_init_h3(collector_internal_t* collector_internal_ptr);
static IOTSECURITY_RESULT _collector_collection_init_m1(collector_internal_t* collector_internal_ptr);
static IOTSECURITY_RESULT _collector_collection_init_m2(collector_internal_t* collector_internal_ptr);
static IOTSECURITY_RESULT _collector_collection_init_l1(collector_internal_t* collector_internal_ptr);
static IOTSECURITY_RESULT _collector_collection_init_collector(collector_internal_t* collector_internal_ptr, const char* name, COLLECTOR_TYPE type, COLLECTOR_PRIORITY priority, struct INIT_DATA_TAG test_data);
static void _collector_collection_get_test_init_array(INIT_FUNCTION** init_array, uint32_t* init_array_size);
static void _collector_collection_factory_upadte_collection_time(collector_t* collector_ptr, uint32_t position);

static INIT_FUNCTION _init_array_all[6] = {
    _collector_collection_init_h1,
    _collector_collection_init_h2,
    _collector_collection_init_h3,
    _collector_collection_init_m1,
    _collector_collection_init_m2,
    _collector_collection_init_l1
};

static INIT_FUNCTION _init_array_no_medium[4] = {
    _collector_collection_init_h1,
    _collector_collection_init_h2,
    _collector_collection_init_h3,
    _collector_collection_init_l1
};

static INIT_FUNCTION _init_array_medium[2] = {
    _collector_collection_init_m1,
    _collector_collection_init_m2
};

static IOTSECURITY_RESULT _collector_collection_init_h1(collector_internal_t* collector_internal_ptr) {
    return _collector_collection_init_collector(collector_internal_ptr, "h1", COLLECTOR_TYPE_TEST, COLLECTOR_PRIORITY_HIGH, mock_collector_collection_factory_test_data[COLLECTOR_H1]);
}

static IOTSECURITY_RESULT _collector_collection_init_h2(collector_internal_t* collector_internal_ptr) {
    return _collector_collection_init_collector(collector_internal_ptr, "h2", COLLECTOR_TYPE_TEST, COLLECTOR_PRIORITY_HIGH, mock_collector_collection_factory_test_data[COLLECTOR_H2]);
}

static IOTSECURITY_RESULT _collector_collection_init_h3(collector_internal_t* collector_internal_ptr) {
    return _collector_collection_init_collector(collector_internal_ptr, "h3", COLLECTOR_TYPE_TEST, COLLECTOR_PRIORITY_HIGH, mock_collector_collection_factory_test_data[COLLECTOR_H3]);
}

static IOTSECURITY_RESULT _collector_collection_init_m1(collector_internal_t* collector_internal_ptr) {
    return _collector_collection_init_collector(collector_internal_ptr, "m1", COLLECTOR_TYPE_TEST, COLLECTOR_PRIORITY_MEDIUM, mock_collector_collection_factory_test_data[COLLECTOR_M1]);
}

static IOTSECURITY_RESULT _collector_collection_init_m2(collector_internal_t* collector_internal_ptr) {
    return _collector_collection_init_collector(collector_internal_ptr, "m2", COLLECTOR_TYPE_TEST, COLLECTOR_PRIORITY_MEDIUM, mock_collector_collection_factory_test_data[COLLECTOR_M2]);
}

static IOTSECURITY_RESULT _collector_collection_init_l1(collector_internal_t* collector_internal_ptr) {
    return _collector_collection_init_collector(collector_internal_ptr, "l1", COLLECTOR_TYPE_TEST, COLLECTOR_PRIORITY_LOW, mock_collector_collection_factory_test_data[COLLECTOR_L1]);
}

static IOTSECURITY_RESULT _collector_collection_init_collector(collector_internal_t* collector_internal_ptr, const char* name, COLLECTOR_TYPE type, COLLECTOR_PRIORITY priority, struct INIT_DATA_TAG test_data) {
    IOTSECURITY_RESULT result = collector_mock_init_with_params(collector_internal_ptr, name, type, priority);

    if (result != IOTSECURITY_RESULT_OK) {
        return result;
    }

    char buffer[50];
    memset(buffer, 0, 50);

    linked_list_event_t_handle event_queue = &(((collector_state_handle)collector_internal_ptr->state)->event_queue);
    for (uint32_t i=0; i < test_data.num_of_events; i++) {
        sprintf(buffer, "%s%d", name, i);
        event_t* event_ptr = event_init("1", buffer, "Periodic", "Security", 0);

        event_build(event_ptr);
        linked_list_event_t_add_last(event_queue, event_ptr);
    }

    return IOTSECURITY_RESULT_OK;
}

static void _collector_collection_get_test_init_array(INIT_FUNCTION** init_array, uint32_t* init_array_size) {
    switch (mock_collector_collection_init_array) {
        case MOCK_COLLECTOR_COLLECTION_FACTORY_ALL:
            *init_array = _init_array_all;
            *init_array_size = sizeof(_init_array_all) / sizeof(INIT_FUNCTION);
            break;
        case MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM:
            *init_array = _init_array_medium;
            *init_array_size = sizeof(_init_array_medium) / sizeof(INIT_FUNCTION);
            break;
        case MOCK_COLLECTOR_COLLECTION_FACTORY_NO_MEDIUM:
            *init_array = _init_array_no_medium;
            *init_array_size = sizeof(_init_array_no_medium) / sizeof(INIT_FUNCTION);
            break;
        case MOCK_COLLECTOR_COLLECTION_FACTORY_EMPTY:
        default:
            *init_array = NULL;
            *init_array_size = 0;
    }
    return;
}

void collector_collection_factory_init() {
    memset(mock_collector_collection_factory_test_data, 0, sizeof(struct INIT_DATA_TAG)*6);
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_ALL;
    return;
}

void collector_collection_factory_init_test_data(uint32_t h1, uint32_t h2, uint32_t h3, uint32_t m1, uint32_t m2, uint32_t l1) {
    mock_collector_collection_factory_test_data[COLLECTOR_H1].num_of_events = h1;
    mock_collector_collection_factory_test_data[COLLECTOR_H2].num_of_events = h2;
    mock_collector_collection_factory_test_data[COLLECTOR_H3].num_of_events = h3;
    mock_collector_collection_factory_test_data[COLLECTOR_M1].num_of_events = m1;
    mock_collector_collection_factory_test_data[COLLECTOR_M2].num_of_events = m2;
    mock_collector_collection_factory_test_data[COLLECTOR_L1].num_of_events = l1;
}

void _collector_collection_factory_upadte_collection_time(collector_t* collector_ptr, uint32_t position) {
    if (collector_ptr != NULL && mock_collector_collection_factory_test_data[position].initial_time != 0)
        collector_ptr->last_collected_timestamp = mock_collector_collection_factory_test_data[position].initial_time;
}

IOTSECURITY_RESULT __wrap_collector_collection_factory_get_initialization_array(INIT_FUNCTION** init_array, uint32_t* init_array_size) {
    _collector_collection_get_test_init_array(init_array, init_array_size);
    return IOTSECURITY_RESULT_OK;
}

IOTSECURITY_RESULT __wrap_collector_collection_internal_init_startup_time(collector_collection_t* collector_collection_ptr) {
    _collector_collection_factory_upadte_collection_time(collector_collection_get_collector_by_priority(collector_collection_ptr, "h1"), COLLECTOR_H1);
    _collector_collection_factory_upadte_collection_time(collector_collection_get_collector_by_priority(collector_collection_ptr, "h2"), COLLECTOR_H2);
    _collector_collection_factory_upadte_collection_time(collector_collection_get_collector_by_priority(collector_collection_ptr, "h3"), COLLECTOR_H3);
    _collector_collection_factory_upadte_collection_time(collector_collection_get_collector_by_priority(collector_collection_ptr, "m1"), COLLECTOR_M1);
    _collector_collection_factory_upadte_collection_time(collector_collection_get_collector_by_priority(collector_collection_ptr, "m2"), COLLECTOR_M2);
    _collector_collection_factory_upadte_collection_time(collector_collection_get_collector_by_priority(collector_collection_ptr, "l1"), COLLECTOR_L1);
    return IOTSECURITY_RESULT_OK;
}