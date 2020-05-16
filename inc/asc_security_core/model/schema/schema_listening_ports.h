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

#ifndef SCHEMA_LISTENING_PORTS_H
#define SCHEMA_LISTENING_PORTS_H


#include "asc_security_core/asc/asc_span.h"
#include "asc_security_core/configuration.h"
#include "asc_security_core/iotsecurity_result.h"

#define SCHEMA_LISTENING_PORTS_EXTRA_DETAILS_ENTRIES 3

typedef struct schema_listening_ports listening_ports_t;

/**
 * @brief Initialize ListeningPortsSchema handle
 *
 * @return listening_ports_t*
 */
listening_ports_t* schema_listening_ports_init();


/**
 * @brief Deinitialize ListeningPortsSchema handle
 *
 * @param data_ptr ListeningPortsSchema handle - listening_ports_t*
 *
 * @return NULL
 */
void schema_listening_ports_deinit(listening_ports_t* data_ptr);


/**
 * @brief Getter schema extra details
 *
 * @param data_ptr   listening_ports_t ptr
 *
 * @return schema extra_details
 */
asc_pair* schema_listening_ports_get_extra_details(listening_ports_t* data_ptr);


/**
 * @brief Setter schema extra details
 *
 * @param data_ptr       listening_ports_t ptr
 * @param extra_details     extra details
 *
 * @return IOTSECRUITY_RESULT
 */
IOTSECURITY_RESULT schema_listening_ports_set_extra_details(listening_ports_t* data_ptr, asc_pair* extra_details);


/**
 * @brief Getter schema protocol
 *
 * @param data_ptr   listening_ports_t ptr
 *
 * @return schema protocol
 */
asc_span schema_listening_ports_get_protocol(listening_ports_t* data_ptr);


/**
 * @brief Setter schema protocol
 *
 * @param data_ptr   listening_ports_t ptr
 * @param protocol      protocol
 *
 * @return IOTSECRUITY_RESULT
 */
IOTSECURITY_RESULT schema_listening_ports_set_protocol(listening_ports_t* data_ptr, char* protocol);


/**
 * @brief Getter schema local address
 *
 * @param data_ptr   listening_ports_t ptr
 *
 * @return schema local address
 */
asc_span schema_listening_ports_get_local_address(listening_ports_t* data_ptr);


/**
 * @brief Setter schema local address
 *
 * @param data_ptr       listening_ports_t ptr
 * @param local_address     local address
 *
 * @return IOTSECRUITY_RESULT
 */
IOTSECURITY_RESULT schema_listening_ports_set_local_address(listening_ports_t* data_ptr, char* local_address);


/**
 * @brief Getter schema local port
 *
 * @param data_ptr   listening_ports_t ptr
 *
 * @return schema local port
 */
asc_span ListeningPortsSchema_GetLocalPort(listening_ports_t* data_ptr);


/**
 * @brief Setter schema local port
 *
 * @param data_ptr    listening_ports_t ptr
 * @param local_port     local port
 *
 * @return IOTSECRUITY_RESULT
 */
IOTSECURITY_RESULT schema_listening_ports_set_local_port(listening_ports_t* data_ptr, char* local_port);


/**
 * @brief Getter schema remote address
 *
 * @param data_ptr   listening_ports_t ptr
 *
 * @return schema remote address
 */
asc_span schema_listening_ports_get_remote_address(listening_ports_t* data_ptr);


/**
 * @brief Setter schema remote address
 *
 * @param data_ptr       listening_ports_t ptr
 * @param remote_address    remote address
 *
 * @return IOTSECRUITY_RESULT
 */
IOTSECURITY_RESULT schema_listening_ports_set_remote_address(listening_ports_t* data_ptr, char* remote_address);


/**
 * @brief Getter schema remote port
 *
 * @param data_ptr   listening_ports_t ptr
 *
 * @return schema remote port
 */
asc_span schema_listening_ports_get_remote_port(listening_ports_t* data_ptr);


/**
 * @brief Setter schema remote port
 *
 * @param data_ptr   listening_ports_t ptr
 * @param remote_port   remote port
 *
 * @return IOTSECRUITY_RESULT
 */
IOTSECURITY_RESULT schema_listening_ports_set_remote_port(listening_ports_t* data_ptr, char* remote_port);


#endif /* SCHEMA_LISTENING_PORTS_H */
