#pragma once
#define SECURITY_WIN32
#include <Security.h>
#include <Credssp.h>
#include "schannel.h"

class ClientConn
{
public:
	int			iIndex;
	WCHAR		szPackageName[40];
	WCHAR		szSelectedPackageName[40];
	CtxtHandle	hctxt;

	SecPkgContext_NegotiationInfo SecPkgNegInfo;
	SecPkgContext_PackageInfo SecPackageInfo;
	SecPkgContext_Sizes SecPkgContextSizes;

	BOOL Initialize();
	BOOL ReceiveTestType(int * iTestType);
	BOOL ReceivePackageName();
	BOOL Authenticate();
	BOOL GetContextInfo();
	BOOL GetContextSizes();
	BOOL ImpersonateClient();
	BOOL SecureSend(LPWSTR pMessage, DWORD cbMessage);

	void GetTheTime(LPWSTR pszTime);

	ClientConn(int i);
	~ClientConn();

	//Error handling
	DWORD	dwErrorCode;
	WCHAR	szErrorLocation[255];
	WCHAR	szErrorMessage[255];



private:
	BOOL fNewConversation;
	BOOL ValidSecurityContext;

	BOOL SendMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf);
	BOOL ReceiveMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD *pcbRead);
	BOOL SendBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf);
	BOOL ReceiveBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD *pcbRead);
	BOOL AddServerCertInfo(PSCHANNEL_CRED pSchannelCred);
	BOOL CreateSelfSignedMachineCert(LPWSTR pszSubjectName);

	void LogError(LONG dwError, LPCWSTR pszErrorLocation);

	void PrintHexDump(DWORD length, PBYTE buffer);

	BOOL GenServerContext(
		BYTE		*pIn,
		DWORD		cbIn,
		BYTE		*pOut,
		DWORD		*pcbOut,
		BOOL		*pfDone,
		CredHandle	*hcred,
		CtxtHandle	*hctxt);

	BOOL Encrypt(
		PBYTE pMessageToEncrypt,
		ULONG cbMessageToEncrypt,
		BYTE ** ppEncryptedMessage,
		ULONG * pcbEncryptedMessage);

};
