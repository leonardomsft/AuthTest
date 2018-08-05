#include <Winsock2.h>
#include <iostream>
#include "Clients.h"
#include "Header.h"

//#define SEC_SUCCESS(Status) ((Status) >= 0)

ClientConn::ClientConn(int i)
{
	iIndex = i;
}

ClientConn::~ClientConn()
{
	shutdown(Connections[iIndex], SD_BOTH);

	closesocket(Connections[iIndex]);

	wprintf(L"Client %d: Disconnected.\n", iIndex);

	InterlockedDecrement(&ConnectionCount);
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


BOOL ClientConn::ReceiveTestType(int * iTestType)
{
	CHAR RecvBuffer[4] = {};

	int iResult = 0;

	iResult = recv(Connections[iIndex], RecvBuffer, sizeof(RecvBuffer), NULL);

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

	*iTestType = atoi(RecvBuffer);

	//validate

	if (*iTestType < 1 || *iTestType > 2)
	{
		wprintf(L"Client %d: Invalid TestType.\n", iIndex);

		return false;
	}

	return true;
}

BOOL ClientConn::ReceivePackageName()
{
	int iResult = 0;

	iResult = recv(Connections[iIndex], (CHAR *)szPackageName, 40 * sizeof(WCHAR), NULL);

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

	return true;
}

BOOL ClientConn::SendAuthResult(int iAuthResult)
{
	CHAR SendBuffer[4] = {};

	sprintf_s(SendBuffer, "%d", iAuthResult);

	int iResult = 0;

	iResult = send(Connections[iIndex], SendBuffer, sizeof(iAuthResult), NULL);

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
		wprintf(L"Client %d: QueryContextAttributes failed: 0x%08x\n", iIndex, ss);

		return false;
	}

	return true;

}


BOOL ClientConn::Authenticate()
{
	SECURITY_STATUS	ss;
	DWORD			cbIn, cbOut;
	BOOL			fdone = false;
	TimeStamp		Lifetime;
	PSecPkgInfo		pkgInfo;
	CredHandle		hcred;
	PBYTE			pInBuf = nullptr;
	PBYTE			pOutBuf = nullptr;

	//for credssp
	PSEC_WINNT_AUTH_IDENTITY_W	pSpnegoCred = NULL;
	PSCHANNEL_CRED				pSchannelCred = NULL;
	PCREDSSP_CRED				pCred = NULL;


	fNewConversation = true;

	//Validate the Package Name
	ss = QuerySecurityPackageInfo(
		szPackageName,
		&pkgInfo);

	if (!SEC_SUCCESS(ss))
	{
		wprintf(L"Client %d: QuerySecurityPackageInfo failed for package %s, error 0x%08x\n", iIndex, szPackageName, ss);

		goto CleanUp;
	}

	//
	//Additional steps if CredSSP
	//

	if (!_wcsicmp(szPackageName, L"CredSSP"))
	{

		//1. Build Schannel cred structure
				
		pSchannelCred = (PSCHANNEL_CRED)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(SCHANNEL_CRED));

		if (NULL == pSchannelCred)
		{
			wprintf(L"Client %d: malloc failed for pSchannelCred, error 0x%08x\n", iIndex, GetLastError());

			goto CleanUp;
		}

		pSchannelCred->dwVersion = SCHANNEL_CRED_VERSION;

		//Obtain a machine cert in the MY store
		if (!AddServerCertInfo(pSchannelCred))
		{
			wprintf(L"Client %d: AddServerCertInfo failed, error 0x%08x\n", iIndex, GetLastError());

			goto CleanUp;

		}

		//2. Build CREDSSP cred structure

		pCred = (PCREDSSP_CRED)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(CREDSSP_CRED));

		if (NULL == pCred)
		{
			wprintf(L"Client %d: malloc failed for pCred, error 0x%08x\n", iIndex, GetLastError());

			goto CleanUp;
		}

		pCred->pSpnegoCred = pSpnegoCred;
		pCred->pSchannelCred = pSchannelCred;


	}//if credssp



	 //Acquire Credentials

	ss = AcquireCredentialsHandle(
		NULL,
		szPackageName,
		SECPKG_CRED_INBOUND,
		NULL,
		(PVOID)pCred,	//pAuthData 
		NULL,
		NULL,
		&hcred,
		&Lifetime);

	if (!SEC_SUCCESS(ss))
	{
		wprintf(L"Client %d: AcquireCredentialsHandle failed: 0x%08x\n", iIndex, ss);

		goto CleanUp;
	}

	//Allocate in and out buffers

	pInBuf = (PBYTE)malloc(pkgInfo->cbMaxToken + sizeof(MessageType));
	pOutBuf = (PBYTE)malloc(pkgInfo->cbMaxToken + sizeof(MessageType));

	if (NULL == pInBuf || NULL == pOutBuf)
	{
		wprintf(L"Client %d: Memory allocation failed.\n", iIndex);

		goto CleanUp;
	}


	//Syncronize with the Client
	if (!SendAuthResult(MTReady))
	{
		goto CleanUp;
	}


	//
	//Server-side loop of AcceptSecurityContext (client side is InitializeSecurityContext)
	//

	while (!fdone)
	{
		if (!ReceiveMsg(
			Connections[iIndex],
			pInBuf,
			pkgInfo->cbMaxToken,
			&cbIn))
		{
			wprintf(L"Client %d: ReceiveMsg failed.\n", iIndex);

			break;
		}

		if (*pInBuf == MTError)
		{
			break;

		}


		cbOut = pkgInfo->cbMaxToken;

		if (!GenServerContext(
			pInBuf,
			cbIn,
			pOutBuf,
			&cbOut,
			&fdone,
			&hcred,
			&hctxt))
		{
			wprintf(L"Client %d: GenServerContext failed.\n", iIndex);

			*pOutBuf = MTError;
		}
		else
		{
			*pOutBuf = MTToken;
		}

		if (fdone && *pOutBuf == MTToken)
		{
			*pOutBuf = MTLastToken;
		}

		if (*pOutBuf == MTLastToken && *pInBuf == MTLastToken)
		{
			//Both sides are done. No need to send anymore messages
			break;
		}


		fNewConversation = false;

		if (!SendMsg(
			Connections[iIndex],
			pOutBuf,
			cbOut))
		{
			wprintf(L"Client %d: SendMsg failed.\n", iIndex);

			break;
		}
	}

	


CleanUp:

	if (fdone)
	{
		if (!GetContextInfo())  //Populate szSelectedPackageName
		{
			fdone = false;
		}
	}
	else
	{
		SendAuthResult(MTError);  //Inform the result to the client
	}


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

		if (NULL != pSchannelCred->paCred)
		{
			CERT_CONTEXT CertCtx = **(pSchannelCred->paCred);

			CertCloseStore(CertCtx.hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);

			free(pSchannelCred->paCred);
		}

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

	return fdone;
}  // end Authenticate


BOOL ClientConn::GenServerContext(
	BYTE		*pIn,
	DWORD		cbIn,
	BYTE		*pOut,
	DWORD		*pcbOut,
	BOOL		*pfDone,
	CredHandle	*hcred,
	CtxtHandle	*hctxt)
{
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	SecBufferDesc     OutBuffDesc;
	SecBuffer         OutSecBuff;
	SecBufferDesc     InBuffDesc;
	SecBuffer         InSecBuff;
	ULONG             ContextAttributes = ASC_REQ_CONFIDENTIALITY | ASC_REQ_DELEGATE | ASC_REQ_CONNECTION;


	//----------------------------------------------------------------
	//  Prepare output buffers.

	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers = 1;
	OutBuffDesc.pBuffers = &OutSecBuff;

	OutSecBuff.cbBuffer = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer = pOut + sizeof(MessageType);

	//----------------------------------------------------------------
	//  Prepare input buffers.

	InBuffDesc.ulVersion = 0;
	InBuffDesc.cBuffers = 1;
	InBuffDesc.pBuffers = &InSecBuff;

	InSecBuff.cbBuffer = cbIn - sizeof(MessageType);
	InSecBuff.BufferType = SECBUFFER_TOKEN;
	InSecBuff.pvBuffer = pIn + sizeof(MessageType);

	if (fVerbose)
		wprintf(L"Client %d: Token buffer received (%lu bytes):\n", iIndex, InSecBuff.cbBuffer);

	PrintHexDump(InSecBuff.cbBuffer, (PBYTE)InSecBuff.pvBuffer);

	ss = AcceptSecurityContext(
		hcred,
		fNewConversation ? NULL : hctxt,
		&InBuffDesc,
		ContextAttributes,
		SECURITY_NATIVE_DREP,
		hctxt,
		&OutBuffDesc,
		&ContextAttributes,
		&Lifetime);

	if (!SEC_SUCCESS(ss))
	{
		wprintf(L"Client %d: AcceptSecurityContext failed: 0x%08x\n", iIndex, ss);

		return false;
	}

	//----------------------------------------------------------------
	//  Complete token if applicable.

	if ((SEC_I_COMPLETE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss))
	{
		ss = CompleteAuthToken(hctxt, &OutBuffDesc);

		if (!SEC_SUCCESS(ss))
		{
			wprintf(L"Client %d: CompleteAuthToken failed: 0x%08x\n", iIndex, ss);

			return false;
		}
	}

	*pcbOut = OutSecBuff.cbBuffer + sizeof(MessageType);

	if (fVerbose)
		wprintf(L"Client %d: Token buffer generated (%lu bytes):\n", iIndex, OutSecBuff.cbBuffer);

	PrintHexDump(OutSecBuff.cbBuffer, (PBYTE)OutSecBuff.pvBuffer);

	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss));

	if (fVerbose)
		wprintf(L"Client %d: AcceptSecurityContext result = 0x%08x\n", iIndex, ss);

	return true;

}  // end GenServerContext


BOOL ClientConn::ImpersonateClient()
{

	wprintf(L"Client %d: Starting impersonation test.\n", iIndex);


	//
	//Call ImpersonateSecurityContext
	//

	SECURITY_STATUS   ss;

	ss = ImpersonateSecurityContext(&hctxt);

	if (!SEC_SUCCESS(ss))
	{
		wprintf(L"Client %d: Impersonate failed: 0x%08x\n", iIndex, ss);

		return false;
	}


	//
	//Call GetUserName
	//

	WCHAR szUserName[256] = {};

	DWORD cbUserName = 256;

	if (!GetUserName(szUserName, &cbUserName))
	{
		wprintf(L"Client %d: GetUserName failed: 0x%08x\n", iIndex, GetLastError());

		return false;

	}

	wprintf(L"Client %d: Client connected as : %s\n", iIndex, szUserName);


	//
	//Revert to Self
	//

	ss = RevertSecurityContext(&hctxt);

	if (!SEC_SUCCESS(ss))
	{
		wprintf(L"Client %d: Revert to Self failed: 0x%08x\n", iIndex, ss);

		return false;
	}


	return true;
}

void ClientConn::GetTheTime(LPWSTR pszTime)
{

	SYSTEMTIME st;
	WCHAR szTime[40];

	GetLocalTime(&st);

	swprintf_s(szTime, L"The time now is %02d:%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	wcscpy_s(pszTime, 40, szTime);

}

BOOL ClientConn::SecureSend(LPWSTR pMessage, DWORD cbMessage)
{

	wprintf(L"Client %d: Starting encryption test. \n", iIndex);

	//size in bytes of all wide characters in pMessage, excluding the null terminator
	cbMessage = 2 * (DWORD)wcslen(pMessage);

	//pointer to receive the encrypted Message
	PBYTE pEncryptedMessage = nullptr;
	//size of the data
	DWORD cbEncryptedData = 0;

	Encrypt(
		(PBYTE)pMessage,	//pointer to the message to encrypt
		cbMessage,			//size in bytes of all wide characters in pMessage, excluding the null terminator
		&pEncryptedMessage,	//local pointer to receive the output (an offset in pMessage)
		&cbEncryptedData);	//local int to receive the count of bytes of the output

							//-----------------------------------------------------------------   
							//  Send the encrypted data to client.


	if (!SendMsg(
		Connections[iIndex],
		pEncryptedMessage,
		cbEncryptedData))
	{
		wprintf(L"Client %d: SendMsg failed. Error 0x%08x \n", iIndex, GetLastError());

		return false;
	}

	if (pEncryptedMessage)
		free(pEncryptedMessage);

	return true;

}


//
//  This function allocates a buffer. The caller needs to free it.
//

BOOL ClientConn::Encrypt(
	PBYTE pMessage,		//pointer to original message
	ULONG cbMessage,	//size of pMessage in bytes
	BYTE ** ppOutput,	//pointer to pointer to receive the output
	ULONG * pcbOutput)  //pointer to receive the size of the output in bytes
{
	SECURITY_STATUS   ss;
	SecBufferDesc     BuffDesc;		//describes an array of SecBuffer structures
	SecBuffer         SecBuff[2];	//array of 2 SecBuffer structures
	ULONG             ulQop = 0;	//Quality of Protection
	PBYTE             pSigBuffer;	//pointer to the signature
	ULONG             SigBufferSize = SecPkgContextSizes.cbSecurityTrailer; //Size of the signature


																			//  The format of an encrypted message consists of 3 portions:
																			//
																			//  1                                2                  3
																			//  --------------------------------------------------------------------------
																			//  | Size of Signature (4 bytes)    | Signature        |  User data         |
																			//  --------------------------------------------------------------------------


																			//wprintf(L"Client %d: Data before encryption: %s\n", iIndex, pMessage);
																			//wprintf(L"Client %d: Length of data before encryption: %d \n", iIndex, cbMessage);

																			//  Allocate a buffer 
	*ppOutput = (PBYTE)malloc(sizeof(DWORD) + SigBufferSize + cbMessage);

	if (!*ppOutput)
	{
		wprintf(L"Client %d: Memory allocation error 0x%08x. SecureSend -> Encrypt -> malloc\n", iIndex, GetLastError());

		return false;
	}

	//2. The signature starts 4 bytes after the beginning
	pSigBuffer = *ppOutput + sizeof(DWORD);

	//Initialize buffer desc
	BuffDesc.ulVersion = SECBUFFER_VERSION;
	BuffDesc.cBuffers = 2;
	BuffDesc.pBuffers = SecBuff;

	//First element receives the signature.
	//The signature is required for decryption, must be sent across the wire
	SecBuff[0].pvBuffer = pSigBuffer;			//pointer to buffer, offset by 4 bytes
	SecBuff[0].cbBuffer = SigBufferSize;		//size
	SecBuff[0].BufferType = SECBUFFER_TOKEN;	//type

												//Second element receives the user data
												//Encryption is done in-place. Plain data is replaced with encrypted data
	SecBuff[1].pvBuffer = pMessage;			//pointer to original message
	SecBuff[1].cbBuffer = cbMessage;		//size
	SecBuff[1].BufferType = SECBUFFER_DATA;	//type

	ss = EncryptMessage(
		&hctxt,
		ulQop,
		&BuffDesc,
		0);

	if (!SEC_SUCCESS(ss))
	{
		wprintf(L"Client %d: EncryptMessage failed: 0x%08x\n", iIndex, ss);
		return(FALSE);
	}


	//1. Set the size of the signature
	*((DWORD *)*ppOutput) = SecBuff[0].cbBuffer;

	//3. Set the User data
	memcpy(*ppOutput + SecBuff[0].cbBuffer + sizeof(DWORD), pMessage, cbMessage);

	//Set total size of encrypted message (1 + 2 + 3)
	*pcbOutput = sizeof(DWORD) + SecBuff[0].cbBuffer + cbMessage;

	wprintf(L"Client %d: The message has been encrypted (%lu bytes). \n", iIndex, *pcbOutput);

	PrintHexDump(*pcbOutput, *ppOutput);

	return true;

}  // end Encrypt


BOOL ClientConn::SendMsg(
	SOCKET s,
	PBYTE pBuf,
	DWORD cbBuf)
{
	if (0 == cbBuf)
		return true;

	//----------------------------------------------------------------
	//  Send the size of the message first, so recv on the other side knows how many bytes to expect.

	if (!SendBytes(
		s,
		(PBYTE)&cbBuf,
		sizeof(cbBuf)))
	{
		return false;
	}

	//----------------------------------------------------------------    
	//  Send the body of the message.

	if (!SendBytes(
		s,
		pBuf,
		cbBuf))
	{
		return false;
	}

	return(TRUE);
} // end SendMsg    

BOOL ClientConn::ReceiveMsg(
	SOCKET s,
	PBYTE pBuf,
	DWORD cbBuf,
	DWORD *pcbRead)
{
	DWORD cbRead;
	DWORD cbData;

	//-----------------------------------------------------------------
	//  Retrieve the number of bytes in the message first.

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

	//----------------------------------------------------------------
	//  Retrieve the full message.

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

	return(TRUE);
}  // end ReceiveMsg    

BOOL ClientConn::SendBytes(
	SOCKET s,
	PBYTE pBuf,
	DWORD cbBuf)
{
	//printf("  Starting SendBytes...");

	PBYTE pTemp = pBuf;
	int cbSent, cbRemaining = cbBuf;

	if (0 == cbBuf)
	{
		return true;
	}

	while (cbRemaining)
	{
		cbSent = send(
			s,
			(const char *)pTemp,
			cbRemaining,
			0);

		if (SOCKET_ERROR == cbSent)
		{
			wprintf(L"Client %d: send failed: %u\n", iIndex, GetLastError());

			return false;
		}

		pTemp += cbSent;
		cbRemaining -= cbSent;
	}
	//printf("done.\n");


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
		cbRead = recv(
			s,
			(char *)pTemp,
			cbRemaining,
			0);
		
		if (NULL == cbRead)
		{
			break;
		}

		if (SOCKET_ERROR == cbRead)
		{
			wprintf(L"Client %d: recv failed: %u\n", iIndex, GetLastError());
			
			return false;
		}

		cbRemaining -= cbRead;
		pTemp += cbRead;
	}

	*pcbRead = cbBuf - cbRemaining;

	return true;
}  // end ReceivesBytes




void ClientConn::PrintHexDump(DWORD length, PBYTE buffer)
{
	if (fVerbose == false)
	{
		return;
	}

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


BOOL ClientConn::AddServerCertInfo(PSCHANNEL_CRED pSchannelCred)
{
	WCHAR szSubjectName[] = L"AuthTestServer";
	HCERTSTORE  hCertStore = NULL;
	PCCERT_CONTEXT * ppCertContext = NULL; // server cert array

	if (!pSchannelCred)
	{
		return false;
	}


	// Open Computer's store 

	hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		X509_ASN_ENCODING,
		0,
		CERT_SYSTEM_STORE_LOCAL_MACHINE,
		L"MY");

	if (GetLastError() == ERROR_ACCESS_DENIED)
	{
		wprintf(L"Client %d: CertOpenStore failed with ACCESS_DENIED. CredSSP requires elevation on the server side.\n", iIndex);

		return false;
	}

	if (!hCertStore)
	{
		wprintf(L"Client %d: CertOpenStore failed: 0x%08x\n", iIndex, GetLastError());

		return false;

	}


	ppCertContext = (PCCERT_CONTEXT *)malloc(sizeof(PCCERT_CONTEXT));

	if (!ppCertContext)

	{
		wprintf(L"Client %d: malloc (ppCertContext) failed: 0x%08x\n", iIndex, GetLastError());

		return false;

	}

	ZeroMemory(ppCertContext, sizeof(PCCERT_CONTEXT));


	// Find a machine certificate matching szSubjectName

	ppCertContext[0] = CertFindCertificateInStore(
		hCertStore,
		X509_ASN_ENCODING,
		0,
		CERT_FIND_SUBJECT_STR,
		szSubjectName,
		ppCertContext[0]);

	if (!ppCertContext[0])
	{

		//Machine certificate not found. Attempt to create a self-signed one

		wprintf(L"Client %d: Could not find a machine certificate matching the criteria (Subject Name = %s)\n", iIndex, szSubjectName);

		wprintf(L"Client %d: Attempting to create a self-signed certificate...\n", iIndex);

		if (!CreateSelfSignedMachineCert(szSubjectName))
		{

			wprintf(L"Client %d: Could not create a self-signed machine certificate for CredSSP.\n", iIndex);

			return false;
		}

		//Create succeeded. Re-try

		//We have to close and reopen the store. Long sigh...

		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);

		hCertStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			X509_ASN_ENCODING,
			0,
			CERT_SYSTEM_STORE_LOCAL_MACHINE,
			L"MY");


		if (!hCertStore)
		{
			wprintf(L"Client %d: CertOpenStore failed: 0x%08x\n", iIndex, GetLastError());

			return false;

		}

		//Re-try

		ppCertContext[0] = CertFindCertificateInStore(
			hCertStore,
			X509_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_STR,
			szSubjectName,
			ppCertContext[0]);

		if (!ppCertContext[0])
		{
			//we should never be here.

			wprintf(L"Client %d: Something went wrong. Aborting\n", iIndex);

			return false;
		}

	}

	wprintf(L"Client %d: Found machine certificate (Subject Name = %s)\n", iIndex, szSubjectName);

	pSchannelCred->cCreds = 1;
	pSchannelCred->paCred = ppCertContext;
	pSchannelCred->dwCredFormat = 0;


	//Cleanup dilema:
	//
	//1. If we close the store with flag CERT_CLOSE_STORE_CHECK_FLAG, we leak a handle.
	//2. If we close the store with flag CERT_CLOSE_STORE_FORCE_FLAG, we free the credentials before we can use it.
	//
	//Therefore, the store needs to be closed by the caller function.

	//CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);


	return true;

}// end AddServerCertInfo



BOOL ClientConn::CreateSelfSignedMachineCert(LPWSTR pszSubjectName)
{

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;


	//Open existing key container matching pszSubjectName

	if (!CryptAcquireContext(&hCryptProv, pszSubjectName, NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))
	{

		//key container not found. Attempt to create one

		if (!CryptAcquireContext(&hCryptProv, pszSubjectName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
		{

			wprintf(L"Client %d: CryptAcquireContext failed: 0x%08x\n", iIndex, GetLastError());

			return false;
		}


	}


	//Generate new 2048-bit key pair

	if (!CryptGenKey(hCryptProv, AT_SIGNATURE, 2 * RSA1024BIT_KEY, &hKey))
	{
		wprintf(L"Client %d: CryptGenKey failed: 0x%08x\n", iIndex, GetLastError());

		return false;
	}

	// Clean up  

	if (hKey)
	{
		CryptDestroyKey(hKey);
	}

	if (hCryptProv)
	{
		CryptReleaseContext(hCryptProv, 0);
	}



	PCCERT_CONTEXT pCertContext = NULL;
	PBYTE pbEncoded = NULL;
	HCERTSTORE hStore = NULL;

	LPCTSTR pszX500 = L"CN=AuthTestServer";
	DWORD cbEncoded = 0;


	//probe how many bytes we need

	if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
	{

		wprintf(L"Client %d: CertStrToName failed: 0x%08x\n", iIndex, GetLastError());

		return false;
	}

	//Allocate a buffer 

	if (!(pbEncoded = (PBYTE)malloc(cbEncoded)))
	{

		wprintf(L"Client %d: CreateSelfSignedMachineCert -> malloc failed: 0x%08x\n", iIndex, GetLastError());

		return false;
	}

	//Encode the issuer string

	if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
	{

		wprintf(L"Client %d: CertStrToName failed: 0x%08x\n", iIndex, GetLastError());

		return false;
	}


	// Prepare certificate Subject for self-signed certificate

	CERT_NAME_BLOB SubjectIssuerBlob;
	memset(&SubjectIssuerBlob, 0, sizeof(SubjectIssuerBlob));
	SubjectIssuerBlob.cbData = cbEncoded;
	SubjectIssuerBlob.pbData = pbEncoded;

	// Prepare key provider structure for self-signed certificate

	CRYPT_KEY_PROV_INFO KeyProvInfo;
	memset(&KeyProvInfo, 0, sizeof(KeyProvInfo));
	KeyProvInfo.pwszContainerName = pszSubjectName;
	KeyProvInfo.pwszProvName = NULL;
	KeyProvInfo.dwProvType = PROV_RSA_FULL;
	KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
	KeyProvInfo.cProvParam = 0;
	KeyProvInfo.rgProvParam = NULL;
	KeyProvInfo.dwKeySpec = AT_SIGNATURE;

	// Prepare algorithm structure for self-signed certificate

	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
	memset(&SignatureAlgorithm, 0, sizeof(SignatureAlgorithm));
	CHAR szObjId[] = szOID_RSA_SHA1RSA;
	SignatureAlgorithm.pszObjId = szObjId;

	// Prepare Expiration date for self-signed certificate
	//Start time is 5 minutes ago, to tolerate clients with skewed time
	//End time is 5 years from now.

	SYSTEMTIME StartTime, EndTime;
	GetSystemTime(&EndTime);
	StartTime = EndTime;
	StartTime.wMinute -= 5;
	EndTime.wYear += 5;

	// Create self-signed certificate

	pCertContext = CertCreateSelfSignCertificate(NULL, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, &StartTime, &EndTime, 0);

	if (!pCertContext)
	{
		wprintf(L"Client %d: CertCreateSelfSignCertificate failed: 0x%08x\n", iIndex, GetLastError());

		return false;
	}


	// Open machine's cert store

	hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");

	if (!hStore)
	{
		wprintf(L"Client %d: CertOpenStore failed: 0x%08x\n", iIndex, GetLastError());

		return false;
	}


	// Add self-signed cert to the store

	if (!CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0))
	{

		wprintf(L"Client %d: CertAddCertificateContextToStore failed: 0x%08x\n", iIndex, GetLastError());

		return false;
	}

	wprintf(L"Client %d: Self-signed certificate created successfully in the machine store.\n", iIndex);


	// Clean up

	if (!pbEncoded)
	{
		free(pbEncoded);
	}

	if (pCertContext)
	{
		CertFreeCertificateContext(pCertContext);
	}

	if (hStore)
	{
		CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
	}

	return true;

}// end CreateSelfSignedMachineCert


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
