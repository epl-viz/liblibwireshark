#ifndef DEFS_H_
#define DEFS_H_

#include <stdio.h>
#include <stdlib.h>

#define S(x) #x
#define S_(x) S(x)
#define S__LINE__ S_(__LINE__)

#define my_assert(cond, ...) do { \
                                    if (cond) break; \
                                    fprintf(stderr, "[" __FILE__ ":" S__LINE__ "] " __VA_ARGS__); \
                                    exit (1); \
                                } while(0)
#endif
