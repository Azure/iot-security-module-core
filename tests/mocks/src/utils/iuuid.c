#include <string.h>
#include "../../inc/utils/iuuid.h"


int __wrap_iuuid_generate(char* buf) {
    const char uuid[] = "42b894a1-0e3f-4962-b79c-7dae124c7269";
    strncpy(buf, uuid, sizeof(uuid));
    return 0;
}