#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

BOOL CloseHandles(void);
