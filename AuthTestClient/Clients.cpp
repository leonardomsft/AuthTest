#include "stdafx.h"
#include "Clients.h"


ClientConn::ClientConn(int i, LPWSTR pszServerName, int iDestPort, LPWSTR pszTargetName, LPWSTR pszPackageName)
{
	iIndex = i;

	wcscpy_s(szServerName, 255, pszServerName);

	iPort = iDestPort;

	wcscpy_s(szTargetName, 255, pszTargetName);

	wcscpy_s(szPackageName, 40, pszPackageName);

	fNewConversation = true;
}


ClientConn::~ClientConn()
{
	shutdown(s, SD_BOTH);

	closesocket(s);

	wprintf(L"Client %d: Disconnected.\n", iIndex);

}


BOOL ClientConn::Initialize()
{

	if (!fNewConversation)
	{
		DeleteSecurityContext(&hctxt);

		fNewConversation = true;
	}

	return true;
}


BOOL ClientConn::Connect()
{
	LONG iResult = 0;

	WSAData wsaData;
	ADDRINFOW * AddrInfo = NULL;
	ADDRINFOW hints;
	WCHAR szPort[6] = {};
	WCHAR szResolvedIP[46] = {};
	DWORD cbResolvedIP = sizeof(szResolvedIP);

	// prepare params

	//wcscpy_s(szServerName, 255, szServerName);

	swprintf_s(szPort, L"%d", iPort);


	// Winsock startup

	if (NULL != WSAStartup(MAKEWORD(2, 2), &wsaData)) {

		LogError(WSAGetLastError(), L"WSAStartup");

		return false;

	}

	// Initialize hints, which is passed to getaddrinfo() 

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;     //todo: consider support for ipv6
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;


	if (GetAddrInfo(szServerName,
		szPort,
		&hints,
		&AddrInfo))
	{

		LogError(WSAGetLastError(), L"GetAddrInfoW");

		return false;
	}


	//Move next
	if (AddrInfo->ai_next)
		AddrInfo = AddrInfo->ai_next;


	// Print the resolved IP

	iResult = WSAAddressToString(AddrInfo->ai_addr,
		AddrInfo->ai_addrlen,
		NULL,
		szResolvedIP,
		&cbResolvedIP);

	if (iResult)
	{
		LogError(WSAGetLastError(), L"WSAAddressToString");

		return false;
	}

	wprintf(L"Name %s resolved to IP %s\n", szServerName, szResolvedIP);


	// Create socket 

	s = WSASocket(AddrInfo->ai_family, AddrInfo->ai_socktype, AddrInfo->ai_protocol, NULL, NULL, NULL);

	if (s == INVALID_SOCKET) {

		LogError(WSAGetLastError(), L"WSASocket");

		return false;

	}
	wprintf(L"socket succeed.\n");


	// Connect

	iResult = WSAConnect(s, AddrInfo->ai_addr, AddrInfo->ai_addrlen, NULL, NULL, NULL, NULL);

	if (iResult == SOCKET_ERROR)
	{
		LogError(WSAGetLastError(), L"WSAConnect");

		closesocket(s);

		if (AddrInfo)
			FreeAddrInfoW(AddrInfo);

		return false;
	}
	wprintf(L"WSAConnect succeed.\n");


	if (AddrInfo)
		FreeAddrInfoW(AddrInfo);

	return true;
}

BOOL ClientConn::SendTestType(int iTestType)
{
	CHAR SendBuffer[4] = {};

	sprintf_s(SendBuffer, "%d", iTestType);

	int iResult = 0;

	iResult = send(s, SendBuffer, sizeof(iTestType), NULL);

	if (iResult < 0)
	{
		LogError(WSAGetLastError(), L"send failed. Connection error.");

		return false;
	}

	if (iResult == 0)
	{
		LogError(WSAGetLastError(), L"send failed. Connection gracefully closed.");

		return false;
	}

	return true;

}

BOOL ClientConn::SendPackageName()
{

	int iResult = 0;

	//wcscpy_s(szPackageName, 40, pszPackageName);

	iResult = send(s, (CHAR *)szPackageName, sizeof(szPackageName), NULL);

	if (iResult < 0)
	{
		LogError(WSAGetLastError(), L"send failed. Connection error.");

		return false;
	}

	if (iResult == 0)
	{
		LogError(WSAGetLastError(), L"send failed. Connection gracefully closed.");

		return false;
	}

	return true;

}

BOOL ClientConn::ReceiveAuthResult(int * iAuthResult)
{
	CHAR RecvBuffer[4] = {};

	int iResult = 0;

	iResult = recv(s, RecvBuffer, sizeof(RecvBuffer), NULL);

	if (iResult < 0)
	{
		wprintf(L"Client %d: Connection error: %d.\n", iIndex, GetLastError());

		return false;
	}

	if (iResult == 0)
	{
		wprintf(L"Client %d: Connection gracefully closed.\n", iIndex);

		return false;
	}

	*iAuthResult = atoi(RecvBuffer);

	//validate

	if (*iAuthResult < 0 || *iAuthResult > 1)
	{
		wprintf(L"Client %d: Invalid AuthResult.\n", iIndex);

		return false;
	}


	return true;
}


BOOL ClientConn::GetContextInfo()
{
	SECURITY_STATUS	ss;

	if (!_wcsicmp(szPackageName, L"CredSSP"))
	{
		//CredSSP

		ss = QueryContextAttributes(
			&hctxt,
			SECPKG_ATTR_NEGOTIATION_PACKAGE,
			&SecPackageInfo);

		if (!SEC_SUCCESS(ss))
		{
			wprintf(L"Client %d: QueryContextAttributes failed: 0x%08x\n", iIndex, ss);

			return false;
		}

		wcscpy_s(szSelectedPackageName, 40, SecPackageInfo.PackageInfo->Name);

		FreeContextBuffer(SecPackageInfo.PackageInfo);

	}
	else
	{
		//Other packages

		ss = QueryContextAttributes(
			&hctxt,
			SECPKG_ATTR_NEGOTIATION_INFO,
			&SecPkgNegInfo);

		if (!SEC_SUCCESS(ss))
		{
			wprintf(L"Client %d: QueryContextAttributes failed: 0x%08x\n", iIndex, ss);

			return false;
		}

		wcscpy_s(szSelectedPackageName, 40, SecPkgNegInfo.PackageInfo->Name);

		FreeContextBuffer(SecPkgNegInfo.PackageInfo);

	}


	ss = QueryContextAttributes(
		&hctxt,
		SECPKG_ATTR_KEY_INFO,
		&SecPackageKeyInfo);

	if (!SEC_SUCCESS(ss))
	{
		wprintf(L"Client %d: QueryContextAttributes failed: 0x%08x\n", iIndex, ss);

		return false;
	}
	wcscpy_s(szEncryptAlgorithmName, 40, SecPackageKeyInfo.sEncryptAlgorithmName);
	KeySize = SecPackageKeyInfo.KeySize;
	wcscpy_s(szSignatureAlgorithmName, 40, SecPackageKeyInfo.sSignatureAlgorithmName);

	FreeContextBuffer(SecPackageKeyInfo.sEncryptAlgorithmName);
	FreeContextBuffer(SecPackageKeyInfo.sSignatureAlgorithmName);

	return true;

}


BOOL ClientConn::GetContextSizes()
{
	SECURITY_STATUS	ss;

	ss = QueryContextAttributes(
		&hctxt,
		SECPKG_ATTR_SIZES,
		&SecPkgContextSizes);

	if (!SEC_SUCCESS(ss))
	{
		LogError(ss, L"QueryContextAttributes, SECPKG_ATTR_SIZES");

		return false;
	}

	return true;

}


BOOL ClientConn::Authenticate()
{
	SECURITY_STATUS	ss;

	TimeStamp		Lifetime;
	BOOL			fDone = false;
	DWORD			cbOut = 0;
	DWORD			cbIn = 0;
	PBYTE			pInBuf = nullptr;
	PBYTE			pOutBuf = nullptr;
	int				iServerAuthResult = 0;


	//for credssp or Explicit Credentials
	PSEC_WINNT_AUTH_IDENTITY_W	pSpnegoCred = NULL;
	PSCHANNEL_CRED				pSchannelCred = NULL;
	PCREDSSP_CRED				pCred = NULL;


	//Validate the Package Name
	ss = QuerySecurityPackageInfo(
		szPackageName,
		&pkgInfo);

	if (!SEC_SUCCESS(ss))
	{
		LogError(ss, L"QuerySecurityPackageInfo");

		goto CleanUp;
	}

	//
	//Additional steps if CredSSP
	//

	if (!_wcsicmp(pkgInfo->Name, L"CredSSP"))
	{

		//1. Build SPNEGO cred structure

		pSpnegoCred = (PSEC_WINNT_AUTH_IDENTITY_W)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(SEC_WINNT_AUTH_IDENTITY_W));

		if (NULL == pSpnegoCred)
		{
			LogError(ss, L"LocalAlloc, pSpnegoCred");

			goto CleanUp;
		}

		pSpnegoCred->Domain = (unsigned short *)NULL;
		pSpnegoCred->DomainLength = (unsigned long)0;
		pSpnegoCred->Password = (unsigned short *)NULL;
		pSpnegoCred->PasswordLength = (unsigned long)0;
		pSpnegoCred->User = (unsigned short *)NULL;
		pSpnegoCred->UserLength = (unsigned long)0;
		pSpnegoCred->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;


		//2. Build Schannel cred structure

		pSchannelCred = (PSCHANNEL_CRED)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(SCHANNEL_CRED));

		if (NULL == pSchannelCred)
		{
			LogError(ss, L"LocalAlloc, pSchannelCred");

			goto CleanUp;
		}

		pSchannelCred->dwVersion = SCHANNEL_CRED_VERSION;
		pSchannelCred->cCreds = 0;
		pSchannelCred->paCred = NULL;


		//3. Build CREDSSP cred structure

		pCred = (PCREDSSP_CRED)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(CREDSSP_CRED));

		if (NULL == pCred)
		{
			LogError(ss, L"LocalAlloc, pCred");

			goto CleanUp;
		}

		pCred->pSpnegoCred = pSpnegoCred;
		pCred->pSchannelCred = pSchannelCred;


	}//if credssp


	//Acquire Credentials

	ss = AcquireCredentialsHandle(
		NULL,
		szPackageName,
		SECPKG_CRED_OUTBOUND,
		NULL,
		(PVOID)pCred,	//pAuthData 
		NULL,
		NULL,
		&hCred,
		&Lifetime);

	if (!(SEC_SUCCESS(ss)))
	{
		LogError(ss, L"AcquireCredentialsHandle");

		goto CleanUp;
	}


	//Allocate in and out buffers
	pInBuf = (PBYTE)malloc(pkgInfo->cbMaxToken);
	pOutBuf = (PBYTE)malloc(pkgInfo->cbMaxToken);

	if (NULL == pInBuf || NULL == pOutBuf)
	{
		LogError(GetLastError(), L"malloc, pInBuf/pOutBuf");

		goto CleanUp;
	}

	//pInBuff is NULL the first time
	cbOut = pkgInfo->cbMaxToken;


	//
	//client-side loop of InitializeSecurityContext (Server side is AcceptSecurityContext)
	//

	while (!fDone)
	{

		//
		//Nothing to receive in a new conversation
		//

		if (!fNewConversation)
		{

			if (!ReceiveMsg(
				s,
				pInBuf,
				pkgInfo->cbMaxToken,
				&cbIn))
			{
				//The error has already been captured. Just return.

				break;
			}

		}

		cbOut = pkgInfo->cbMaxToken;

		if (!GenClientContext(
			pInBuf,
			cbIn,
			pOutBuf,
			&cbOut,
			&fDone))
		{
			//The error has already been captured. Just return.

			break;
		}

		fNewConversation = false;

		if (!SendMsg(
			s,
			pOutBuf,
			cbOut))
		{
			//The error has already been captured. Just return.

			break;
		}
	}

	//Check if the server succeeded
	
	if (!fDone || !ReceiveAuthResult(&iServerAuthResult) || iServerAuthResult == 0)
	{
		fDone = false;

		goto CleanUp;
	}



	//Populate szSelectedPackageName

	if (!GetContextInfo())
	{
		goto CleanUp;

	}


CleanUp:

	if (pInBuf)
	{
		free(pInBuf);
	}

	if (pOutBuf)
	{
		free(pOutBuf);
	}

	if (pCred)
	{

		if (pCred->pSchannelCred)
		{
			LocalFree(pCred->pSchannelCred);
		}


		if (pCred->pSpnegoCred)
		{
			LocalFree(pCred->pSpnegoCred);
		}

		LocalFree(pCred);
	}

	//Release context buffer
	FreeContextBuffer(pkgInfo);

	return fDone;
}



BOOL ClientConn::GenClientContext(
	BYTE       *pIn,
	DWORD       cbIn,
	BYTE       *pOut,
	DWORD      *pcbOut,
	BOOL       *pfDone)

{
	SECURITY_STATUS		ss;
	TimeStamp			Lifetime;
	SecBufferDesc		OutBuffDesc;
	SecBuffer			OutSecBuff;
	SecBufferDesc		InBuffDesc;
	SecBuffer			InSecBuff;
	ULONG				ContextAttributes = ASC_REQ_CONFIDENTIALITY | ASC_REQ_DELEGATE | ASC_REQ_CONNECTION;


	//
	//  Prepare Out buffer.
	//

	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers = 1;
	OutBuffDesc.pBuffers = &OutSecBuff;

	OutSecBuff.cbBuffer = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer = pOut;

	//
	//  Prepare In buffer.
	//

	InBuffDesc.ulVersion = 0;
	InBuffDesc.cBuffers = 1;
	InBuffDesc.pBuffers = &InSecBuff;

	InSecBuff.cbBuffer = cbIn;
	InSecBuff.BufferType = SECBUFFER_TOKEN;
	InSecBuff.pvBuffer = pIn;

	ss = InitializeSecurityContext(
		&hCred,
		fNewConversation ? NULL : &hctxt,
		(SEC_WCHAR *)szTargetName,
		ContextAttributes,
		NULL,
		SECURITY_NATIVE_DREP,
		fNewConversation ? NULL : &InBuffDesc,
		NULL,
		&hctxt,
		&OutBuffDesc,
		&ContextAttributes,
		&Lifetime);



	if (!SEC_SUCCESS(ss))
	{
		LogError(ss, L"InitializeSecurityContext");

		return false;
	}

	//
	//  If necessary, complete the token.
	//

	if ((SEC_I_COMPLETE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss))
	{
		ss = CompleteAuthToken(&hctxt, &OutBuffDesc);

		if (!SEC_SUCCESS(ss))
		{
			LogError(ss, L"CompleteAuthToken");

			return false;
		}
	}

	*pcbOut = OutSecBuff.cbBuffer;

	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss));

	wprintf(L"Token buffer generated (%lu bytes):\n", OutSecBuff.cbBuffer);
	PrintHexDump(OutSecBuff.cbBuffer, (PBYTE)OutSecBuff.pvBuffer);

	return true;
}


BOOL ClientConn::SendMsg(
	SOCKET s,
	PBYTE pBuf,
	DWORD cbBuf)
{
	if (0 == cbBuf)
		return true;

	//
	//  Send the size of the message first, so recv on the other side knows how many bytes to expect.
	//

	if (!SendBytes(
		s,
		(PBYTE)&cbBuf,
		sizeof(cbBuf)))
	{
		return false;
	}

	//
	//  Now send the body of the message.
	//

	if (!SendBytes(
		s,
		pBuf,
		cbBuf))
	{
		return false;
	}

	return true;
} // end SendMsg    

BOOL ClientConn::ReceiveMsg(
	SOCKET s,
	PBYTE pBuf,
	DWORD cbBuf,
	DWORD *pcbRead)
{
	DWORD cbRead;
	DWORD cbData;

	//
	//  Receive the number of bytes in the message first.
	//

	if (!ReceiveBytes(
		s,
		(PBYTE)&cbData,
		sizeof(cbData),
		&cbRead))
	{
		return false;
	}

	if (sizeof(cbData) != cbRead)
	{
		return false;
	}

	//
	//  Receive the full message.
	//

	if (!ReceiveBytes(
		s,
		pBuf,
		cbData,
		&cbRead))
	{
		return false;
	}

	if (cbRead != cbData)
	{
		return false;
	}

	*pcbRead = cbRead;

	return true;
}  // end ReceiveMsg    

BOOL ClientConn::SendBytes(
	SOCKET s,
	PBYTE pBuf,
	DWORD cbBuf)
{

	PBYTE pTemp = pBuf;
	int cbSent, cbRemaining = cbBuf;

	if (cbBuf == 0)
	{
		return true;
	}

	while (cbRemaining)
	{
		cbSent = send(s, (const char *)pTemp, cbRemaining, 0);

		if (cbSent < 0)
		{
			LogError(WSAGetLastError(), L"send failed. Connection error.");

			return false;
		}

		if (cbSent == 0)
		{
			LogError(WSAGetLastError(), L"send failed. Connection gracefully closed.");

			return false;
		}

		//send success
		pTemp += cbSent;
		cbRemaining -= cbSent;

	}//while

	return true;
}  // end SendBytes

BOOL ClientConn::ReceiveBytes(
	SOCKET s,
	PBYTE pBuf,
	DWORD cbBuf,
	DWORD *pcbRead)
{
	PBYTE pTemp = pBuf;
	int cbRead, cbRemaining = cbBuf;

	while (cbRemaining)
	{
		cbRead = recv(s, (char *)pTemp, cbRemaining, 0);

		if (cbRead < 0)
		{
			LogError(WSAGetLastError(), L"recv failed. Connection error.");

			return false;
		}

		if (cbRead == 0)
		{
			LogError(WSAGetLastError(), L"recv failed. Connection gracefully closed.");

			return false;
		}

		//recv success
		cbRemaining -= cbRead;
		pTemp += cbRead;
	}

	*pcbRead = cbBuf - cbRemaining;

	return true;
}  // end ReceivesBytes



void ClientConn::PrintHexDump(DWORD length, PBYTE buffer)
{
	DWORD i, count, index;
	CHAR rgbDigits[] = "0123456789abcdef";
	CHAR rgbLine[100];
	char cbLine;

	for (index = 0; length;
		length -= count, buffer += count, index += count)
	{
		count = (length > 16) ? 16 : length;

		sprintf_s(rgbLine, 100, "%4.4x  ", index);
		cbLine = 6;

		for (i = 0; i < count; i++)
		{
			rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
			rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
			if (i == 7)
			{
				rgbLine[cbLine++] = ':';
			}
			else
			{
				rgbLine[cbLine++] = ' ';
			}
		}
		for (; i < 16; i++)
		{
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
		}

		rgbLine[cbLine++] = ' ';

		for (i = 0; i < count; i++)
		{
			if (buffer[i] < 32 || buffer[i] > 126)
			{
				rgbLine[cbLine++] = '.';
			}
			else
			{
				rgbLine[cbLine++] = buffer[i];
			}
		}

		rgbLine[cbLine++] = 0;
		printf("%s\n", rgbLine);
	}
}  // end PrintHexDump


PBYTE ClientConn::Decrypt(
	PBYTE              pMessage,
	LPDWORD            pcbMessage)
{
	SECURITY_STATUS   ss;
	SecBufferDesc     BuffDesc;
	SecBuffer         SecBuff[2];
	ULONG             ulQop = 0;
	PBYTE             pDataBuffer;
	PBYTE             pSigBuffer;
	DWORD             SigBufferSize;

	//  The format of an encrypted message consists of 3 portions:
	//
	//  1                                2                  3
	//  --------------------------------------------------------------------------
	//  | Size of Signature (4 bytes)    | Signature        |  User data         |
	//  --------------------------------------------------------------------------

	//1. Get the Size of Signature
	SigBufferSize = *((DWORD *)pMessage);

	printf("data before decryption including trailer (%lu bytes):\n", *pcbMessage);
	PrintHexDump(*pcbMessage, (PBYTE)pMessage);

	//2. Get the signature (required to decrypt the User data)
	pSigBuffer = pMessage + sizeof(DWORD);

	//3. Get the user data
	pDataBuffer = pSigBuffer + SigBufferSize;

	//Set *pcbMessage to the size of just the User data
	*pcbMessage = *pcbMessage - SigBufferSize - sizeof(DWORD);

	//Initialize BuffDesc
	BuffDesc.ulVersion = 0;
	BuffDesc.cBuffers = 2;
	BuffDesc.pBuffers = SecBuff;

	//The first buffer contains the signature
	SecBuff[0].pvBuffer = pSigBuffer;
	SecBuff[0].cbBuffer = SigBufferSize;
	SecBuff[0].BufferType = SECBUFFER_TOKEN;

	//The second buffer contains the user data
	SecBuff[1].pvBuffer = pDataBuffer;
	SecBuff[1].cbBuffer = *pcbMessage;
	SecBuff[1].BufferType = SECBUFFER_DATA;

	//Decryption is done in-place. The encrypted data is replaced with decrypted data
	ss = DecryptMessage(
		&hctxt,
		&BuffDesc,
		0,
		&ulQop);

	if (!SEC_SUCCESS(ss))
	{
		LogError(ss, L"DecryptMessage failed.");
	}

	//Return the position of User data in pMessage
	return pDataBuffer;

} //end Decrypt


BOOL ClientConn::SecureReceive(LPWSTR pMessage, DWORD cbMessage)
{
	//allocate a buffer
	PBYTE EncryptedData = (PBYTE)malloc(cbMessage);

	if (!EncryptedData)
	{
		LogError(GetLastError(), L"malloc");

		return false;
	}

	PBYTE	DecryptedData;  //will be set to an offset into EncryptedData by Decrypt function
	DWORD	cbBytesReceived = 0;
	DWORD	cbEncryptedData = cbMessage;

	//Receive the encrypted message from the server
	if (!ReceiveMsg(
		s,
		EncryptedData,
		cbEncryptedData,
		&cbBytesReceived))
	{
		//the error has already been captured. Just return.

		return false;
	}

	wprintf(L"%d encrypted bytes received \n", cbBytesReceived);

	DecryptedData = Decrypt(
		EncryptedData,
		&cbBytesReceived);

	memcpy_s(pMessage, cbMessage, (PBYTE)DecryptedData, cbBytesReceived);

	//Add null terminator
	pMessage[cbBytesReceived / 2] = '\0';

	//free
	if (EncryptedData)
		free(EncryptedData);

	//wprintf(L"The message from the server is: %s\n", pMessage);

	return true;

}// end SecureReceive


void ClientConn::LogError(LONG dwError, LPCWSTR pszErrorLocation)
{
	wcscpy_s(szErrorLocation, 255, pszErrorLocation);

	dwErrorCode = dwError;

	LPWSTR pszErrorMessage = NULL;

	int iRet = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		dwError,
		NULL,
		(LPWSTR)&pszErrorMessage,
		NULL,
		NULL);

	if (iRet != NULL)
	{
		wcscpy_s(szErrorMessage, iRet + 1, pszErrorMessage);

		LocalFree(pszErrorMessage);

	}

}