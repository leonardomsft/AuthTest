#pragma once

extern SOCKET Connections[MAXWORD];
extern long ConnectionCount;
extern BOOL fVerbose;

#define SEC_SUCCESS(Status) ((Status) >= 0)

enum TestType
{
	Invalid,
	Basic,
	Advanced
};






