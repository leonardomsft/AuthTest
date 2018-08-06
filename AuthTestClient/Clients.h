#pragma once

class ClientConn
{
public:
	int		iIndex;
	WCHAR	szServerName[255];
	int		iPort;
	WCHAR	szTargetName[255];
	WCHAR	szPackageName[40];

	WCHAR	szSelectedPackageName[40];
	WCHAR	szEncryptAlgorithmName[40];
	int		KeySize;
	WCHAR	szSignatureAlgorithmName[40];


	BOOL Initialize();
	BOOL Connect();
	BOOL SendTestType(int iTestType);
	BOOL SendPackageName();
	BOOL Authenticate();
	BOOL GetContextInfo();
	BOOL GetContextSizes();
	BOOL SecureReceive(LPWSTR pMessage, DWORD cbMessage);

	CredHandle	hCred;
	CtxtHandle	hctxt;

	PSecPkgInfo						pkgInfo;
	SecPkgContext_NegotiationInfo	SecPkgNegInfo;
	SecPkgContext_PackageInfo		SecPackageInfo;
	SecPkgContext_KeyInfo			SecPackageKeyInfo;
	SecPkgContext_Sizes				SecPkgContextSizes;

	//Error handling
	LONG	dwErrorCode;
	WCHAR	szErrorLocation[255];
	WCHAR	szErrorMessage[255];

	ClientConn(int i, LPWSTR szServerName, int iDestPort, LPWSTR szTargetName, LPWSTR szPackageName);
	~ClientConn();



private:

	SOCKET s;
	BOOL	fNewConversation;

	BOOL SendMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf);
	BOOL ReceiveMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD *pcbRead);
	BOOL SendBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf);
	BOOL ReceiveBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD *pcbRead);
	BOOL ReceiveAuthResult(int * iAuthResult);

	void LogError(DWORD dwError, LPCWSTR pszErrorLocation);
	void PrintHexDump(DWORD length, PBYTE buffer);

	BOOL GenClientContext(
		BYTE       *pIn,
		DWORD       cbIn,
		BYTE       *pOut,
		DWORD      *pcbOut,
		BOOL       *pfDone);

	PBYTE Decrypt(
		PBYTE              pBuffer,
		LPDWORD            pcbMessage);

};
