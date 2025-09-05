#ifndef LVN_H_
#define LVN_H_

#include <stddef.h>

void * lvn_init(const char *url);
void lvn_run(void * lvn);
void lvn_deinit(void * lvn);

#endif