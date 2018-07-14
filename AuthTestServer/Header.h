#pragma once

extern SOCKET Connections[MAXWORD];
extern int ConnectionCount;
extern BOOL fVerbose;

#define SEC_SUCCESS(Status) ((Status) >= 0)

enum TestType
{
	Basic = 1,
	Advanced
};





