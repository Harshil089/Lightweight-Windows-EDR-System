#pragma once

// This header handles Windows-specific includes and resolves conflicts
// Include this instead of directly including <windows.h>

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <concrt.h>

// Undefine Windows macros that conflict with our EventType enum
#ifdef PROCESS_TERMINATE
#undef PROCESS_TERMINATE
#endif

#ifdef FILE_CREATE
#undef FILE_CREATE
#endif

#ifdef FILE_MODIFY
#undef FILE_MODIFY
#endif

#ifdef FILE_DELETE
#undef FILE_DELETE
#endif

#ifdef NETWORK_CONNECT
#undef NETWORK_CONNECT
#endif

#ifdef NETWORK_DISCONNECT
#undef NETWORK_DISCONNECT
#endif

#ifdef REGISTRY_WRITE
#undef REGISTRY_WRITE
#endif

// Undefine other common Windows macros that might cause conflicts
#ifdef ERROR
#undef ERROR
#endif

#ifdef DEBUG
#undef DEBUG
#endif

#ifdef INFO
#undef INFO
#endif

#ifdef CRITICAL
#undef CRITICAL
#endif

#ifdef WARNING
#undef WARNING
#endif

#endif // _WIN32
