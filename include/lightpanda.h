#ifndef LIGHTPANDA_H_
#define LIGHTPANDA_H_

#include <stddef.h>

size_t lightpanda_app_init(const char *url);
void lightpanda_app_deinit(size_t address);

#endif