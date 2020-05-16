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

#include <stdint.h>
#include <string.h>
#include "asc_security_core/utils/network_utils.h"

static uint32_t ip1234 = 0x04030201;
static uint32_t ip5678 = 0x08070605;

static const char ip1234str[] = "1.2.3.4";
static const char ip5678str[] = "5.6.7.8";

const char* network_utils_inet_ntop(NETWORK_PROTOCOL network_protocol, const void* source, char* destination, uint32_t size) {
  const char* ip_string = *(uint32_t*)source == ip1234 ? ip1234str : ip5678str;
  return strncpy(destination, ip_string, size);
}

int network_utils_inet_pton(NETWORK_PROTOCOL network_protocol, const char* source, void* destination) {
  *(uint32_t*)destination = strncmp(source, ip1234str, sizeof(ip1234str)) == 0 ? ip1234 : ip5678;
  return 1;
}
