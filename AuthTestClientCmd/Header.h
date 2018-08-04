#pragma once

extern BOOL fVerbose;

#define SEC_SUCCESS(Status) ((Status) >= 0)

enum TestType
{
	Basic = 1,
	Advanced
};

enum MessageType
{
	MTInvalid,
	MTToken,
	MTError
};

typedef struct THREADSTRUCT
{
	int		iIndex;
	WCHAR	szServerName[255];
	int		iPort;
	WCHAR	szTargetName[255];
	WCHAR	szPackageName[40];
	TestType TestType;
} THREADSTRUCT;

