#ifndef LIGHTPANDA_H_
#define LIGHTPANDA_H_

#include <stddef.h>

void * lightpanda_app_init(const char *url);
void lightpanda_app_deinit(void * address);

#endif