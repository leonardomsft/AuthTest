#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <iostream>
#include "Header.h"
#include "Clients.h"

//Globals
SOCKET Connections[MAXWORD];
long ConnectionCount = 0;
int MaxConnections = 1000;
BOOL fVerbose = 0;
const WCHAR * szTestType[] = { L"Invalid", L"Basic", L"Advanced" };


//function prototypes
BOOL ClientHandlerThread(int index);
void PrintUsage();
BOOL ParseArguments(int iArgs, WCHAR ** pArgs, PWSTR szAddress, LPINT iPort, LPBOOL fVerbose);


int wmain(int argc, WCHAR * argv[])
{
	int iResult;


	//
	//  Parse arguments and populate local variables
	//
	WCHAR szAddress[16] = {};

	int iPort = 0;



	if (argc == 2 || argc == 3)
	{

		if (!ParseArguments(argc, argv, szAddress, &iPort, &fVerbose))
		{

			PrintUsage();

			return 1;
		}


	}
	else {

		PrintUsage();

		return 1;
	}


	//
	//  Winsock startup
	//
	WSAData wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {

		wprintf(L"WSAStartup failed. Abort.\n");

		return 1;
	}


	//
	//  Initialize the socket 
	//
	SOCKADDR_IN addr;
	int addrlen = sizeof(addr);
	int iIpAddr = INADDR_NONE;

	if (!InetPton(AF_INET, szAddress, &iIpAddr))
	{

		wprintf(L"Invalid IP. Abort\n");

		return 1;
	}

	addr.sin_addr.s_addr = iIpAddr;
	addr.sin_port = htons(iPort);
	addr.sin_family = AF_INET;


	//
	//  create the socket 
	//
	SOCKET sListener = socket(AF_INET, SOCK_STREAM, NULL);

	if (INVALID_SOCKET == sListener)
	{

		wprintf(L"Failed to create socket: %u\n", GetLastError());

		return 1;
	}


	//
	//  bind to the socket
	//
	iResult = bind(sListener, (LPSOCKADDR)&addr, sizeof(addr));

	if (SOCKET_ERROR == iResult)
	{
		wprintf(L"bind failed: %u\n", GetLastError());

		return 1;
	}


	//
	//  Start listening
	//
	iResult = listen(sListener, SOMAXCONN);

	if (SOCKET_ERROR == iResult)
	{
		wprintf(L"listen failed: %u\n", GetLastError());

		return 1;
	}

	wprintf(L"Listening for clients...\nPress CTRL+C to abort.\n");


	//
	//  loop for client connections 
	//
	SOCKET NewConnection;
	HANDLE NewThread;

	for (DWORD i = 0; i <= MAXWORD - 1; i++)
	{

		//
		//  whenever accept returns, there's a new connection 
		//
		NewConnection = accept(sListener, (SOCKADDR*)&addr, &addrlen);

		if (NULL == NewConnection)
		{
			wprintf(L"Client %d: accept failed. Abort\n", i);

			break;
		}

		//
		//  Bail on MaxConnections
		//
		if (ConnectionCount > MaxConnections)
		{
			
			wprintf(L"Client %d: Max server connections reached. Connection rejected.\n", i);

			shutdown(NewConnection, SD_BOTH);

			closesocket(NewConnection);
		}
		else
		{
			wprintf(L"------------------- Client %d connected -------------------\n", i);

			InterlockedIncrement(&ConnectionCount);

			//wprintf(L"ConnectionCount Incremented to: %d\n", ConnectionCount);

			//preserve the connection in the array

			Connections[i] = NewConnection;

			//Handle each client in a separate thread, which is acceptable design for a test tool

			NewThread = CreateThread(
				NULL,
				NULL,
				(LPTHREAD_START_ROUTINE)ClientHandlerThread,
				(LPVOID)(i),
				NULL,
				NULL);

			if (NULL == NewThread) {

				wprintf(L"CreateThread failed: %u\n", GetLastError());

			}


			CloseHandle(NewThread);

		}


		if (i == MAXWORD - 1)
		{
			i = 0;
		}

	}// end loop

	WSACleanup();

}// end Main


BOOL ClientHandlerThread(int index)
{

	ClientConn * pclient = new ClientConn(index);

	WCHAR pMessage[200] = {};
	int cbpMessage = sizeof(pMessage);
	int iTestType = 0;
	TestType TestType;

	BOOL fSuccess;

	while (true)
	{

		//
		//Initialize
		//

		if (pclient->Initialize())
		{
			wprintf(L"Client %d: Starting new test...\n", index);
		}


		//
		//Receive the Test Type from the client
		//

		if (!pclient->ReceiveTestType((int *)&TestType))
		{
			wprintf(L"Client %d: A TestType was not received. Aborting.\n", index);

			goto cleanup;
		}
		wprintf(L"Client %d: TestType requested: %s\n", index, szTestType[TestType]);


		//
		//Receive the PackageName from the client
		//

		if (!pclient->ReceivePackageName())
		{
			wprintf(L"Client %d: Error receiving PackageName. Aborting.\n", index);

			goto cleanup;
		}
		wprintf(L"Client %d: Package requested: %s\n", index, pclient->szPackageName);


		//
		//Authenticate the client
		//

		if (!pclient->Authenticate())
		{
			wprintf(L"Client %d: Authentication Failed. Aborting.\n", index);

			continue;
		}
		wprintf(L"Client %d: Authentication Success!\n", index);


		//
		//Prints the Package selected during authentication
		//

		if (!pclient->GetContextInfo())
		{
			wprintf(L"Client %d: GetContextInfo failed. Aborting.\n", index);

			continue;
		}

		if (!_wcsicmp(pclient->szPackageName, L"CredSSP"))
		{
			wprintf(L"Client %d: Package selected: CredSSP over %s\n", index, pclient->SecPackageInfo.PackageInfo->Name);
		}
		else
		{
			wprintf(L"Client %d: Package selected: %s\n", index, pclient->SecPkgNegInfo.PackageInfo->Name);
		}



		//
		//  Wrap if Basic
		//

		if (TestType == Basic)
		{
			wprintf(L"Client %d: Basic test completed successfully!\n", index);

			continue;
		}


		//
		//Obtain the size of signature and the encryption trailer blocks
		//

		if (!pclient->GetContextSizes())
		{
			wprintf(L"Client %d: GetContextInfo failed. Aborting.\n", index);

			continue;
		}
		wprintf(L"Client %d: Package MaxSignature size: %d, SecurityTrailer size: %d\n", index, pclient->SecPkgContextSizes.cbMaxSignature, pclient->SecPkgContextSizes.cbSecurityTrailer);


		//
		//Impersonation test.
		//

		if (!pclient->ImpersonateClient())
		{
			wprintf(L"Client %d: Impersonation test failed. Aborting.\n", index);

			continue;
		}
		wprintf(L"Client %d: Impersonation test success!\n", index);


		//
		//Send an encrypted message to the client.
		//

		//First get the current time
		pclient->GetTheTime(pMessage);

		if (!pclient->SecureSend(pMessage, cbpMessage))
		{
			wprintf(L"Client %d: Encryption test failed. Aborting.\n", index);

			continue;
		}
		wprintf(L"Client %d: Encryption test succeess!\n", index);

		wprintf(L"Client %d: Advanced test completed successfully!\n", index);


	}//loop



cleanup:

	if (pclient)
		delete pclient;

	return true;

}//end ClientHandlerThread


void PrintUsage()
{
	wprintf(L"\nAuthTest - Autentication test utility \n");
	wprintf(L"Created by Leonardo Fagundes. No rights reserved.\n\n");
	wprintf(L"Usage:\n");
	wprintf(L"AuthTestServer.exe <address>:<port> [-v]\n");
	wprintf(L"  <address>:<port>	IP Address and TCP Port to listen for traffic\n");
	wprintf(L"  -v (optional)		Verbose output\n");
	wprintf(L"\nExample: AuthTestServer.exe 192.168.1.15:7010\n");
	wprintf(L"\nImportant: CredSSP requires elevation.\n\n");

};

BOOL ParseArguments(int iArgs, WCHAR ** pArgs, PWSTR szAddress, LPINT iPort, LPBOOL fVerbose)
{

	//temp string
	WCHAR * szPort = nullptr;

	//the port starts after the colon
	szPort = wcschr(pArgs[1], L':') + 1;

	//subtract 1 to test for success
	if (szPort - 1 == NULL)
	{
		//there's no colon, abort
		return false;

	}

	//Attempt to convert to int
	*iPort = _wtoi(szPort);

	if (*iPort == NULL || *iPort > 65535)
	{
		//not a valid int, abort
		return false;

	}


	//the address is n characters until the colon
	if (wcsncpy_s(szAddress, 16, pArgs[1], szPort - pArgs[1] - 1))
	{
		//the copy failed, abort
		return false;

	}

	//check for -v
	if (iArgs == 3)
	{

		if (!wcscmp(pArgs[2], L"-v"))
		{

			*fVerbose = true;

		}
		else {

			//there's a 2nd argument, but it's not -v, abort
			return false;

		}
	}

	//success
	return true;
}
