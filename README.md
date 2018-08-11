# AuthTest

AuthTest is an authentication test tool for testing the various authentication methods & protocols available in the Windows Operating System.

AuthTest is a two-part tool consisting of a server and a client. The server runs on the destination computer and waits for client connections. The client runs on the source machine and receives all the authentication parameters. The client connects to the server and runs the desired test.

## Client

Use the client to specify the test parameters:

![Alt text](Fig1.png?raw=true "Figure1")


## Server

Use the sever to start listening for client connections:

![Alt text](Fig2.png?raw=true "Figure2")


## Authentication basics

Authentication on Windows is performed through SSPI (Security Support Provider Interface), a set of APIs that conveniently abstracts all the complexities of security-related operations and exposes a standard interface for user-mode and kernel-mode applications.

SSPI offers a variety of authentication packages:

### Negotiate

Negotiate is the most widely used authentication package in the Windows Patform. Negotiate is not an authentication protocol in itself, it analyzes the parameters and selects the most secure protocol available to perform the authentication. 

It first checks if Kerberos can be used by analyzing the Target name provided. If a Target is not specified, or contains an SPN, UPN, or AccountName that cannot be found in Active Directory, NTLM is used.

### Kerberos

Kerberos relies on a trusted third-party (domain controller) to verify the identity of both the client and the server. For this reason, all nodes must be domain joined. From a very high level, the sequence of steps are:

1. Kerberos starts with the client verifying it's own identity with a domain controller by obtaining a TGT (Ticket Granting Ticket). This typically happens at logon and is valid for 10 hours.
2. When the client is ready to perform the authentication, it requests a TGS (Ticket Granting Service) to the domain controller for the specified Target. The Domain controller searches the forest for a user or computer account that matches the Target. If more than one or no account is found, kerberos fails. A failure at this early stage allows the client to attempt NTLM if the Negotiate package is being used. 
3. If the domain controller finds an account matching the Target, it issues a TGS typically valid for 10 hours.
4. The client sends the TGS to the server, which is able to validade it without needing to contact a domain controller. If validation succeeds, both sides have a session key (CtxtHandle) that can be used for establishing a secure channel. Kerberos authentication is then complete.

### NTLM

NTLM is most commonly used between computers not joined to a domain, or as a fallback protocol when Kerberos cannot be used. NTLM relies on a challenge/response mechanism to verify the client's identity. This is the protocol sequence for NTLMv2:

1. The client sends the Username in plaintext to the server.
2. The server generates a 16-byte random number called challenge or NONCE, and sends it to the client.
3. The client generates a unicode uppercase version of the username, and concatenates it to the unicode target (domain name if the machine is domain joined, server name otherwise).
4. HMAC-MD5 is applied to this value using the NT hash of user's password as a key. This results in 128 bit output known as the NTLMv2 hash.
5. The client then generates its own 64 bits challenge by concatenating a timestamp, some target information, and the server challenge.
6. HMAC-MD5 is applied to this value using the NTLMv2 hash as a key (obtained in step 4). This results in 128 bit output, called NTLMv2 Response, which is sent to the server.
9. The Server sends the username, the original challenge, and the NTLMv2 response to the domain controller.
10. The domain controller repeats the same process the client did and compare the results. If they match, the DC confirms the authentication to the server.
11. The server informs the client whether the authentication succeeded or failed. This occurs outside SSPI.

### CredSSP

CredSSP (Credential Security Support Provider) is

## Scenarios


