#pragma once

extern SOCKET Connections[MAXWORD];
extern long ConnectionCount;
extern BOOL fVerbose;
extern BYTE	MessageType;


#define SEC_SUCCESS(Status) ((Status) >= 0)

enum TestType
{
	Invalid,
	Basic,
	Advanced
};

enum MT
{
	MTInvalid,
	MTReady,
	MTToken,
	MTLastToken,
	MTError
};





