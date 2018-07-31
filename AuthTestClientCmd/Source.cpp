//#include <Winsock2.h>
//#include <Ws2tcpip.h>

#include <windows.h>
#include <iostream>
#include "Header.h"
#include "Clients.h"

// Globals
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
		wprintf(L"Client %d: Test Failed. Error Connecting: %d. Aborting.\n", Param->iIndex, pclient->dwErrorCode);
		wprintf(L"Client %d: %s\n", Param->iIndex, pclient->szErrorMessage);

		goto cleanup;
	}
	wprintf(L"Client %d: Connected to server: %s\n", Param->iIndex, pclient->szServerName);

	//
	// Send Test Type
	//

	if (!pclient->SendTestType(TestType))
	{
		wprintf(L"Client %d: Test Failed. Error sending TestType: %d. Aborting.\n", Param->iIndex, pclient->dwErrorCode);
		wprintf(L"Client %d: %s\n", Param->iIndex, pclient->szErrorMessage);

		goto cleanup;
	}
	wprintf(L"Client %d: TestType sent.\n", Param->iIndex);


	//
	// Send Package Name
	//

	if (!pclient->SendPackageName())
	{
		wprintf(L"Client %d: Test Failed. Error sending PackageName: %d. Aborting.\n", Param->iIndex, pclient->dwErrorCode);
		wprintf(L"Client %d: %s\n", Param->iIndex, pclient->szErrorMessage);

		goto cleanup;
	}
	wprintf(L"Client %d: PackageName sent.\n", Param->iIndex);



	//
	// Authenticate
	//

	if (!pclient->Authenticate())
	{
		wprintf(L"Client %d: Test Failed. Error 0x%08x at Authenticate -> %s. \n", Param->iIndex, pclient->dwErrorCode, pclient->szErrorLocation);

		wprintf(L"Client %d: %s\n", Param->iIndex, pclient->szErrorMessage);

		//Allow delegating fresh credentials
		if (pclient->dwErrorCode == SEC_E_DELEGATION_POLICY &&
			!_wcsicmp(pclient->pkgInfo->Name, L"CredSSP"))
		{
			wprintf(L"Client %d: Check CredSSP delegation policy 'Allow delegating fresh credentials'.\n", Param->iIndex);
		}

		//Allow delegating fresh credentials with NTLM
		if (pclient->dwErrorCode == SEC_E_POLICY_NLTM_ONLY &&
			!_wcsicmp(pclient->pkgInfo->Name, L"CredSSP"))
		{
			wprintf(L"Client %d: Check CredSSP delegation policy 'Allow delegating fresh credentials with NTLM-only'.\n", Param->iIndex);
		}


		goto cleanup;
	}
	wprintf(L"Client %d: Authentication Success!\n", Param->iIndex);



	//
	//Prints the Package selected during authentication, Encryption Algorithm, and key size
	//

	if (!pclient->GetContextInfo())
	{
		wprintf(L"Client %d: Test Failed. GetContextInfo failed: 0x%08x.  Aborting.\n", Param->iIndex, pclient->dwErrorCode);
		
		wprintf(L"Client %d: %s\n", Param->iIndex, pclient->szErrorMessage);

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
	wprintf(L"Client %d: Encryption Algorithm: %s %d bits, Signature Algorithm: %s\n", Param->iIndex, pclient->SecPackageKeyInfo.sEncryptAlgorithmName, pclient->SecPackageKeyInfo.KeySize, pclient->SecPackageKeyInfo.sSignatureAlgorithmName);


	//
	//  Wrap if Basic
	//

	if (TestType == Basic)
	{
		wprintf(L"Client %d: Basic test completed successfully!\n", Param->iIndex);

		goto cleanup;
	}


	//
	//Obtain the size of signature and the encryption trailer blocks
	//

	if (!pclient->GetContextSizes())
	{
		wprintf(L"Client %d: Test Failed. GetContextSizes failed: 0x%08x. Aborting.\n", Param->iIndex, pclient->dwErrorCode);

		wprintf(L"Client %d: %s\n", Param->iIndex, pclient->szErrorMessage);

		goto cleanup;
	}
	wprintf(L"Client %d: GetContextSizes success\n", Param->iIndex);



	//
	//Receive an encrypted message from the server.
	//

	if (!pclient->SecureReceive(pMessage, cbMessage))
	{
		wprintf(L"Client %d: Advanced test failed.  Error 0x%08x at SecureReceive -> %s. \n", Param->iIndex, pclient->dwErrorCode, pclient->szErrorLocation);

		wprintf(L"Client %d: %s\n", Param->iIndex, pclient->szErrorMessage);

		goto cleanup;
	}
	wprintf(L"Client %d: SecureReceive succeess! Message: %s\n", Param->iIndex, pMessage);


	//
	//verify if the beginning of the decrypted message matches what we expect
	//

	if (wcsncmp(pMessage, L"The time now is", 15) != NULL)
	{
		wprintf(L"Client %d: Advanced test Failed. Decrypted message not recognized. Error 0x%08x at %s. \n", Param->iIndex, pclient->dwErrorCode, pclient->szErrorLocation);
		
		wprintf(L"Client %d: %s\n", Param->iIndex, pclient->szErrorMessage);

		goto cleanup;
	}
	else
	{
		wprintf(L"Client %d: Impersonation and Encryption success!\n", Param->iIndex);
	}


	wprintf(L"Client %d: Advanced test completed successfully!\n", Param->iIndex);




cleanup:

	if (pclient)
		delete pclient;

	return true;
}