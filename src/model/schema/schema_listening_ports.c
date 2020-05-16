#include <stdlib.h>
#include "asc_security_core/asc/asc_span.h"
#include "asc_security_core/logger.h"
#include "asc_security_core/configuration.h"
#include "asc_security_core/model/schema/schema_listening_ports.h"
#include "asc_security_core/object_pool.h"

#define SCHEMA_LISTENING_PORTS_OBJECT_POOL_COUNT ASC_COLLECTOR_LISTENING_PORTS_MAX_OBJECTS_IN_CACHE

typedef struct schema_listening_ports {
    COLLECTION_INTERFACE(struct schema_listening_ports);
    asc_pair extra_details[SCHEMA_LISTENING_PORTS_EXTRA_DETAILS_ENTRIES];

    asc_span protocol;
    asc_span local_address;
    asc_span local_port;
    asc_span remote_address;
    asc_span remote_port;
} schema_listening_ports_t;

OBJECT_POOL_DECLARATIONS(schema_listening_ports_t, SCHEMA_LISTENING_PORTS_OBJECT_POOL_COUNT);
OBJECT_POOL_DEFINITIONS(schema_listening_ports_t, SCHEMA_LISTENING_PORTS_OBJECT_POOL_COUNT);


listening_ports_t* schema_listening_ports_init() {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    listening_ports_t* data_ptr = NULL;

    data_ptr = object_pool_get(schema_listening_ports_t);
    if (data_ptr == NULL) {
        result = IOTSECURITY_RESULT_MEMORY_EXCEPTION;
        log_error("Failed to allocate schema_listening_ports_t");
        goto cleanup;
    }

    memset(data_ptr, 0, sizeof(schema_listening_ports_t));

    data_ptr->protocol = ASC_SPAN_NULL;
    data_ptr->local_address = ASC_SPAN_NULL;
    data_ptr->local_port = ASC_SPAN_NULL;
    data_ptr->remote_address = ASC_SPAN_NULL;
    data_ptr->remote_port = ASC_SPAN_NULL;

cleanup:
    if (result != IOTSECURITY_RESULT_OK) {
        log_error("Failed to initialize listening ports schema, result=[%d]", result);
    }

    return data_ptr;
}


void schema_listening_ports_deinit(listening_ports_t* data_ptr) {
    if (data_ptr != NULL){
        data_ptr->protocol = ASC_SPAN_NULL;
        data_ptr->local_address = ASC_SPAN_NULL;
        data_ptr->local_port = ASC_SPAN_NULL;
        data_ptr->remote_address = ASC_SPAN_NULL;
        data_ptr->remote_port = ASC_SPAN_NULL;

        object_pool_free(schema_listening_ports_t, data_ptr);
        data_ptr = NULL;
    }
}


asc_pair* schema_listening_ports_get_extra_details(listening_ports_t* data_ptr) {
    asc_pair* result = NULL;

    if (data_ptr != NULL) {
        result = data_ptr->extra_details;
    }

    return result;
}


IOTSECURITY_RESULT schema_listening_ports_set_extra_details(listening_ports_t* data_ptr, asc_pair* extra_details) {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    if (data_ptr == NULL || extra_details == NULL) {
        log_error("Failed to set listening ports schema extra details due to bad argument");
        result = IOTSECURITY_RESULT_BAD_ARGUMENT;
        goto cleanup;
    }

    memcpy(data_ptr->extra_details, extra_details, sizeof(asc_pair) * SCHEMA_LISTENING_PORTS_EXTRA_DETAILS_ENTRIES);

cleanup:
    if (result != IOTSECURITY_RESULT_OK) {
        log_error("Failed to set listening ports schema extra details, result=[%d]", result);
    }

    return result;
}


asc_span schema_listening_ports_get_protocol(listening_ports_t* data_ptr) {
    asc_span result = ASC_SPAN_NULL;

    if (data_ptr != NULL) {
        result = data_ptr->protocol;
    }

    return result;
}


IOTSECURITY_RESULT schema_listening_ports_set_protocol(listening_ports_t* data_ptr, char* protocol) {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    if (data_ptr == NULL || protocol == NULL) {
        log_error("Failed to set listening ports schema protocol due to bad argument");
        result = IOTSECURITY_RESULT_BAD_ARGUMENT;
        goto cleanup;
    }

    data_ptr->protocol = asc_span_from_str(protocol);

cleanup:
    if (result != IOTSECURITY_RESULT_OK) {
        log_error("Failed to set listening ports schema protocol, result=[%d]", result);
    }

    return result;
}


asc_span schema_listening_ports_get_local_address(listening_ports_t* data_ptr) {
    asc_span result = ASC_SPAN_NULL;

    if (data_ptr != NULL) {
        result = data_ptr->local_address;
    }

    return result;
}


IOTSECURITY_RESULT schema_listening_ports_set_local_address(listening_ports_t* data_ptr, char* local_address) {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    if (data_ptr == NULL || local_address == NULL) {
        log_error("Failed to set listening ports schema local address due to bad argument");
        result = IOTSECURITY_RESULT_BAD_ARGUMENT;
        goto cleanup;
    }

    data_ptr->local_address = asc_span_from_str(local_address);

cleanup:
    if (result != IOTSECURITY_RESULT_OK) {
        log_error("Failed to set listening ports schema local address, result=[%d]", result);
    }

    return result;
}


asc_span ListeningPortsSchema_GetLocalPort(listening_ports_t* data_ptr) {
    asc_span result = ASC_SPAN_NULL;

    if (data_ptr != NULL) {
        result = data_ptr->local_port;
    }

    return result;
}


IOTSECURITY_RESULT schema_listening_ports_set_local_port(listening_ports_t* data_ptr, char* local_port) {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    if (data_ptr == NULL || local_port == NULL) {
        log_error("Failed to set listening ports schema local port due to bad argument");
        result = IOTSECURITY_RESULT_BAD_ARGUMENT;
        goto cleanup;
    }

    data_ptr->local_port = asc_span_from_str(local_port);

cleanup:
    if (result != IOTSECURITY_RESULT_OK) {
        log_error("Failed to set listening ports schema local port, result=[%d]", result);
    }

    return result;
}


asc_span schema_listening_ports_get_remote_address(listening_ports_t* data_ptr) {
    asc_span result = ASC_SPAN_NULL;

    if (data_ptr != NULL) {
        result = data_ptr->remote_address;
    }

    return result;
}


IOTSECURITY_RESULT schema_listening_ports_set_remote_address(listening_ports_t* data_ptr, char* remote_address) {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    if (data_ptr == NULL || remote_address == NULL) {
        log_error("Failed to set listening ports schema remote address due to bad argument");
        result = IOTSECURITY_RESULT_BAD_ARGUMENT;
        goto cleanup;
    }

    data_ptr->remote_address = asc_span_from_str(remote_address);

cleanup:
    if (result != IOTSECURITY_RESULT_OK) {
        log_error("Failed to set listening ports schema remote address, result=[%d]", result);
    }

    return result;
}


asc_span schema_listening_ports_get_remote_port(listening_ports_t* data_ptr) {
    asc_span result = ASC_SPAN_NULL;

    if (data_ptr != NULL) {
        result = data_ptr->remote_port;
    }

    return result;
}


IOTSECURITY_RESULT schema_listening_ports_set_remote_port(listening_ports_t* data_ptr, char* remote_port) {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    if (data_ptr == NULL || remote_port == NULL) {
        log_error("Failed to set listening ports schema remote port due to bad argument");
        result = IOTSECURITY_RESULT_BAD_ARGUMENT;
        goto cleanup;
    }

    data_ptr->remote_port = asc_span_from_str(remote_port);

cleanup:
    if (result != IOTSECURITY_RESULT_OK) {
        log_error("Failed to set listening ports schema remote port, result=[%d]", result);
    }

    return result;
}
