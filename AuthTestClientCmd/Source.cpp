//#include <Winsock2.h>
//#include <Ws2tcpip.h>

#include <windows.h>
#include <iostream>
#include "Header.h"
#include "Clients.h"

// Globals
//int cbMaxMessage = 12000;
BOOL fVerbose = 0;



//function prototypes
BOOL ClientHandlerThread(LPVOID _param);
BOOL ParseArguments(int iArgs, WCHAR ** pArgs, THREADSTRUCT * _param, LPBOOL fVerbose);
void PrintUsage();

void PrintUsage()
{
	wprintf(L"\nAuthTest - Autentication test utility \n");
	wprintf(L"Created by Leonardo Fagundes. No rights reserved.\n\n");
	wprintf(L"Usage:\n");
	wprintf(L"AuthTestCmd.exe -s <Server Name> -p <Port> -t <Target Name> -a <Package Name>Where:\n");
	wprintf(L"  <Server Name>               Computer Name or IP address where AuthTestServer.exe is running\n");
	wprintf(L"  <TCP Port>                  TCP port in which AuthTestServer.exe is listening\n");
	wprintf(L"  <Target Name>               The account or SPN under which AuthTestServer.exe is running\n");
	wprintf(L"  <Package Name> (optional)   The authentication package to be used: Negotiate (default), NTLM, Kerberos, or CredSSP\n");
	wprintf(L"  -advanced (optional)        Type of test to perform. Basic tests authentication. Advanced tests authentication, impersonation, and encryption\n");
	wprintf(L"  -v (optional)               Verbose output\n\n");
	wprintf(L"Example 1: AuthTestCmd.exe -s webportal.contoso.com -p 7010 -t https/webportal.contoso.com -a Kerberos\n");
	wprintf(L"Example 2: AuthTestCmd.exe -s webportal.contoso.com -p 7010 -t MickeyM -a Negotiate\n");
	wprintf(L"Example 3: AuthTestCmd.exe -s myServer -p 7010 -t bob@contoso.com -a Negotiate -Advanced -v\n");
	wprintf(L"Example 4: AuthTestCmd.exe -s myServer -p 7010 -t contoso\\bob\n\n");
	wprintf(L"Important: For CredSSP the server needs to be elevated.\n");
};

BOOL ParseArguments(int iArgs, WCHAR ** pArgs, THREADSTRUCT * _param, LPBOOL fVerbose)
{
	BOOL fs = false, fp = false, ft = false;

	//Assume Negotiate
	wcscpy_s(_param->szPackageName, L"Negotiate");

	//Assume basic test
	_param->TestType = Basic;

	//Assume no verbosity
	*fVerbose = false;

	for (int i = 1; i < iArgs; i++)
	{

		if (!_wcsicmp(pArgs[i], L"-s"))
		{
			fs = true;

			wcscpy_s(_param->szServerName, pArgs[i + 1]);

			i++;
		}

		if (!_wcsicmp(pArgs[i], L"-p"))
		{
			fp = true;

			_param->iPort = _wtoi(pArgs[i + 1]);

			i++;
		}

		if (!_wcsicmp(pArgs[i], L"-t"))
		{
			ft = true;

			wcscpy_s(_param->szTargetName, pArgs[i + 1]);

			i++;
		}

		if (!_wcsicmp(pArgs[i], L"-a"))
		{
			wcscpy_s(_param->szPackageName, pArgs[i + 1]);

			i++;
		}

		if (!_wcsicmp(pArgs[i], L"-advanced"))
		{
			_param->TestType = Advanced;
		}

		if (!_wcsicmp(pArgs[i], L"-v"))
		{
			*fVerbose = true;
		}

	}//for loop

	 //validation
	if (!fs || !fp || !ft ||
		wcsnlen(_param->szServerName, 255) < 2 ||
		_param->iPort < 1 ||
		_param->iPort > MAXWORD ||
		wcsnlen(_param->szTargetName, 255) < 2 ||
		(_wcsicmp(_param->szPackageName, L"Negotiate") &&
			_wcsicmp(_param->szPackageName, L"NTLM") &&
			_wcsicmp(_param->szPackageName, L"Kerberos") &&
			_wcsicmp(_param->szPackageName, L"CredSSP")))
	{
		return false;
	}

	return true;
}


int wmain(int argc, WCHAR * argv[])
{

	THREADSTRUCT * _param = new THREADSTRUCT;

	if (argc >= 7)
	{
		if (!ParseArguments(argc, argv, _param, &fVerbose))
		{

			PrintUsage();

			return 1;
		}
	}
	else
	{
		PrintUsage();

		return 1;
	}


	HANDLE NewThread;

	for (int i = 0; i < 1; i++)
	{

		_param->iIndex = i;


		NewThread = CreateThread(
			NULL,
			NULL,
			(LPTHREAD_START_ROUTINE)ClientHandlerThread,
			(LPVOID)_param,
			NULL,
			NULL);

		if (NULL == NewThread) {

			wprintf(L"CreateThread failed: %u\n", GetLastError());

		}

		WaitForSingleObject(NewThread, INFINITE);


		CloseHandle(NewThread);

	}//for loop


	if (_param)
		delete _param;

}



BOOL ClientHandlerThread(LPVOID _param)
{
	//cast _param into local Param
	THREADSTRUCT * Param = (THREADSTRUCT *)_param;

	ClientConn * pclient = new ClientConn(
		Param->iIndex,
		Param->szServerName,
		Param->iPort,
		Param->szTargetName,
		Param->szPackageName);

	WCHAR pMessage[200];
	int cbMessage = sizeof(pMessage);

	TestType TestType = Param->TestType;


	//
	// Connect to the server
	//

	if (!pclient->Connect())
	{
		wprintf(L"Client %d: Error Connecting. Aborting.\n", Param->iIndex);

		goto cleanup;
	}
	wprintf(L"Client %d: Connected to server: %s\n", Param->iIndex, pclient->szServerName);

	//
	// Send Test Type
	//

	if (!pclient->SendTestType(TestType))
	{
		wprintf(L"Client %d: Error sending TestType. Aborting.\n", Param->iIndex);

		goto cleanup;
	}
	wprintf(L"Client %d: TestType sent.\n", Param->iIndex);


	//
	// Send Package Name
	//

	if (!pclient->SendPackageName())
	{
		wprintf(L"Client %d: Error sending PackageName. Aborting.\n", Param->iIndex);

		goto cleanup;
	}
	wprintf(L"Client %d: PackageName sent.\n", Param->iIndex);



	//
	// Authenticate
	//

	if (!pclient->Authenticate())
	{
		wprintf(L"Client %d: Error 0x%08x at Authenticate -> %s. \n", Param->iIndex, pclient->dwErrorCode, pclient->szErrorLocation);

		//Allow delegating fresh credentials
		if (pclient->dwErrorCode == SEC_E_DELEGATION_POLICY &&
			!_wcsicmp(pclient->pkgInfo->Name, L"CredSSP"))
		{
			wprintf(L"Client %d: Check CredSSP delegation policy at Computer Configuration\\Administrative Templates\\System\\Credential Delegation\\Allow delegating fresh credentials.\n", Param->iIndex);
		}

		//Allow delegating fresh credentials with NTLM
		if (pclient->dwErrorCode == SEC_E_POLICY_NLTM_ONLY &&
			!_wcsicmp(pclient->pkgInfo->Name, L"CredSSP"))
		{
			wprintf(L"Client %d: Check CredSSP delegation policy at Computer Configuration\\Administrative Templates\\System\\Credential Delegation\\Allow delegating fresh credentials with NTLM-only server authentication.\n", Param->iIndex);
		}


		goto cleanup;
	}
	wprintf(L"Client %d: Authentication Success!\n", Param->iIndex);



	//
	//Prints the Package selected during authentication
	//

	if (!pclient->GetContextInfo())
	{
		wprintf(L"Client %d: GetContextInfo failed. Aborting.\n", Param->iIndex);

		goto cleanup;
	}

	if (!_wcsicmp(pclient->szPackageName, L"CredSSP"))
	{
		wprintf(L"Client %d: Package selected: CredSSP over %s\n", Param->iIndex, pclient->SecPackageInfo.PackageInfo->Name);

	}
	else
	{
		wprintf(L"Client %d: Package selected: %s\n", Param->iIndex, pclient->SecPkgNegInfo.PackageInfo->Name);
	}


	//
	//  Wrap if Basic
	//

	if (TestType == Basic)
	{
		goto cleanup;
	}


	//
	//Obtain the size of signature and the encryption trailer blocks
	//

	if (!pclient->GetContextSizes())
	{
		wprintf(L"Client %d: GetContextSizes failed. Aborting.\n", Param->iIndex);

		goto cleanup;
	}
	wprintf(L"Client %d: Package MaxSignature size: %d, SecurityTrailer size: %d\n", Param->iIndex, pclient->SecPkgContextSizes.cbMaxSignature, pclient->SecPkgContextSizes.cbSecurityTrailer);



	//
	//Receive an encrypted message from the server.
	//

	if (!pclient->SecureReceive(pMessage, cbMessage))
	{
		wprintf(L"Client %d: SecureReceive failed. Aborting.\n", Param->iIndex);

		goto cleanup;
	}
	wprintf(L"Client %d: SecureReceive succeess! Message: %s\n", Param->iIndex, pMessage);


cleanup:

	if (pclient)
		delete pclient;

	return true;
}