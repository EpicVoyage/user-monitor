/* Written by:	Daga <daga@epicvoyage.org>
 * Date:		May 7th, 2008
 *
 * This project sponsored by:
 *
 * Cogent Innovators, LLC
 * http://www.cogentinnovators.com
 *
 * All source and project files are released under the terms of the
 * GNU General Public License (GPL) version 2. Please see the file
 * LICENSE for more information.
 */

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

/* Provide TODOs for ourselves... */
#define STR2(x) #x
#define STR(x) STR2(x)
#define TODO(x) message (__FILE__ " (" STR(__LINE__) "): TODO: " #x)

/* Required header files */
#include <winsock2.h>
#include <Iphlpapi.h>
#include <Ntsecapi.h>
#include <wincrypt.h>
#include <Tlhelp32.h>
#include <windows.h>
#include <shlwapi.h>
#include <string.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <mysql.h>
#include <Sddl.h>
#include <conio.h>
#include <time.h>

/* A couple defines for easily tweaking this program */

#define SERVICENAME "UserMonitor"	/* Appears wherever an application or service name would 
									 * Should NOT exceed 32 characters for RFC 3164 (syslog) */
#define SLEEPTIME	2000			/* milliseconds between user checks */
#define MAXNAME		128				/* XP ignores anything beyond 20, but 2000 allows for more */

#define SQLSERVER	"127.0.0.1"		/* default SQL server if one isn't specified */
#define SQLPORT		3306
#define SQLDB		"usermap"
#define SQLUSER		"monitor"
#define SQLPASS		"DBB25B7C9BAD7A9485" /* "t0ps3cr3t" encoded... for XP or Vista */
#define SQLSSL		0

#define LOGSERVER	"127.0.0.1"
#define LOGPORT		514
#define LOG			0x1 | 0x2	/* 0 = don't log, 1 = log file, 2 = syslog */

/* Defines governing the encryption/decryption of passwords */
#define NCRYPTPSWD			"\x01\x43\157g\x65\x6E\164\xD4"
#define ENCRYPT_ALGORITHM	CALG_RC4
#define ENCRYPT_BLOCK_SIZE	8

#pragma TODO("Built-in certificates expire June 17th, 2023 (15 years/5478 days from creation)")
#define CERT "-----BEGIN CERTIFICATE-----\n\
MIIC/jCCAeYCAQEwDQYJKoZIhvcNAQEFBQAwRTELMAkGA1UEBhMCQVUxEzARBgNV\n\
BAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\n\
ZDAeFw0wODA2MTcwNjU1MTNaFw0yMzA2MTcwNjU1MTNaMEUxCzAJBgNVBAYTAkFV\n\
MRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRz\n\
IFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmAivdzvtX\n\
pwPQvuiTHgOR2rAi5HJjHt+EIcoRwpA8B/seN6O3ydliIr443e9Ob/S1xOSBrJZz\n\
B3dINBrx8sojgBpbg+K62feH8irWos/1mwF/HvWiyGqrgqXAnRdKnSAL1ZZzZeq1\n\
C83jXBzmIIVMB19Y8sCyaCPwYbsrtvdDFaiocrCmWnMJKh2I1SfoEogBGs3A2o3l\n\
WAht3VGV7d9hKz7KyS/kbK2zVawdxMowY4o3NJfkVkMj72BBOwmiUwTeRc7D2vH+\n\
3Os4RRlDlRlLNckbmNq3SqWXMHSavA2QklD94CU105oZ+srITzC9Xu/LDaogr0+e\n\
1uup2UcpsKHJAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAFJBvTf+ts17PlfFf/hF\n\
Y83Rdh6I/kilavh1tsRYBOs5Qju0krTj0Ep+yd3aOjDxy0da8d2ZjUeeYrsuwhpA\n\
dpoYnIlv2HZMVR1iKcnHkFZHHjYg3oIC9YZ6RHbSpgK9AA201knbKheKvgu/U7Nx\n\
SbbW2OQVI+So3Kax/nYb3l6L7+PcpRZHCJEcuBjh5C+97FGJBJVjA8OXs2cLILDt\n\
zjL5qqyEYvjU0+bMnqLHdKXKgNDt3NzstltOiFkgFl3bywmBxTx+5vhj/3jYgL5H\n\
xOLde9/tM51Xi5LyW4seBAc0v7HzB5D+ZAcKNnb1MvVyqhgIein1OrEfWcQgKiIc\n\
PfE=\n\
-----END CERTIFICATE-----"

#define KEY "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEogIBAAKCAQEApgIr3c77V6cD0L7okx4DkdqwIuRyYx7fhCHKEcKQPAf7Hjej\n\
t8nZYiK+ON3vTm/0tcTkgayWcwd3SDQa8fLKI4AaW4Piutn3h/Iq1qLP9ZsBfx71\n\
oshqq4KlwJ0XSp0gC9WWc2XqtQvN41wc5iCFTAdfWPLAsmgj8GG7K7b3QxWoqHKw\n\
plpzCSodiNUn6BKIARrNwNqN5VgIbd1Rle3fYSs+yskv5Gyts1WsHcTKMGOKNzSX\n\
5FZDI+9gQTsJolME3kXOw9rx/tzrOEUZQ5UZSzXJG5jat0qllzB0mrwNkJJQ/eAl\n\
NdOaGfrKyE8wvV7vyw2qIK9PntbrqdlHKbChyQIDAQABAoIBADuEO8XiFyptrmiA\n\
iVF1SUJZbRyVWo0+3FO66X9EigF7uwQyXnfd3hnY6unoZ4tviARC+smi3q2O160D\n\
QUXNDbt8ifaVagwjaSNMJx+cb4JWeErjBp29zMCArnxH1bnia0LS6IWm3GbcPIxu\n\
0c2PizqeyghRv9Q2kev0ne4mQq/B2EwG5myOVDva2sSnANXVWQ6yFGO/38C6PIc9\n\
YRP61sGqowO4/WSUwaDtHJNmf3dyUPC1GyudB5Dr8fuALiAy52maFK3NMx/UNyRt\n\
fAiZcOuzhkzwJLXDZjPCoVrKjC9ZgDe+AK17FsfVDsxQWRk6TEEfieCD6EqdM2Fn\n\
EqwQRAECgYEAztTVVhlar9xrt0FIrYEkea8Re6MyfZsccwcyxCaAl26rnYUeH7LB\n\
H3gDiRZr65RjfmLBptVuAqMmJZToGuseugBGic3e0zGUimkFrgb9SgS+UzyDI86V\n\
uDXCOSRKMRVaKoXJApHCd3/FeUHW2HUU3CNERbm+JzrHH6mwRMffHhkCgYEAzXj5\n\
HEc3XUGsSNLRMMh8aA4aBci2aFGet/0tYcBb/ihZv/i/Avi6kTh1SoIgniFtsatq\n\
iBrvBB7zNeKaeel8jjIYCuk9DBgTkXCf53dIIBtyS8QrDTlVAQBogsptmfRm9kEF\n\
sq9FICFFMnri+W5Xyfb6K9UN02wbrEnJbvQ4tzECgYAmWeCU7m6aXUy71icbxO52\n\
gbfELSaXk8NasOMA7AK8EZFQy/Yh+otEwoQlTzsDm6g3LyipPrn/UzEnlszS8PXp\n\
l1N9CedfUboxT/f1pOYia26/EGFgqlWoqo8w+UGoiEUHzXbQOybL8a00Jrknuc38\n\
Y62tIBvaOlPh0x0UI9uDQQKBgEm3FOgoRJyYaw7VU2eFBdzu8jcRAx/56E9p7VYc\n\
hORx5YER5LVUNtrSvoG0na8dnxUWwmmCAC4iTG8QlQsX0S/SmP2RH+2u1ZZgKX4J\n\
NT8PmbnE7w0XfH+XfecuaJPLMwU13q10ZABa71Bk9fk2tRgoGyiOjx9CscrlzfaY\n\
d6CBAoGAXQRe3maADvWT17yVCSPYNYawAD5h7AykVVUpsDXCB61UQDdWDtzfk7OW\n\
nlW3mxwWseApmH3SfXQpwBupxiSuKq9KEzijnmsSyWqCJzIMAZ30aWAEqiYeXaZl\n\
bDThl9xphD7OWJCx0Ec8HdwC4YKZ5j0X9JKTaXFhKUTZQgBO2m0=\n\
-----END RSA PRIVATE KEY-----"

/* Windows API functions which may or may not be available depending on the OS version
 *
 * Advapi32.dll: */
SC_HANDLE (WINAPI *pOpenSCManager)(LPCTSTR lpMachineName, LPCTSTR lpDatabaseName, DWORD dwDesiredAccess);
SC_HANDLE (WINAPI *pCreateService)(SC_HANDLE hSCManager, LPCTSTR lpServiceName, LPCTSTR lpDisplayName,
								  DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType,
								  DWORD dwErrorControl, LPCTSTR lpBinaryPathName, LPCTSTR lpLoadOrderGroup,
								  LPDWORD lpdwTagId, LPCTSTR lpDependencies, LPCTSTR lpServiceStartName,
								  LPCTSTR lpPassword);
SC_HANDLE (WINAPI *pOpenService)(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess);
BOOL (WINAPI *pQueryServiceStatus)(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus);
BOOL (WINAPI *pSetServiceStatus)(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus);
BOOL (WINAPI *pControlService)(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
BOOL (WINAPI *pDeleteService)(SC_HANDLE hService);
BOOL (WINAPI *pCloseServiceHandle)(SC_HANDLE hSCObject);

BOOL (WINAPI *pGetTokenInformation)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
								LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DWORD (WINAPI *pGetLengthSid)(PSID pSid);
BOOL (WINAPI *pCopySid)(DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid);
BOOL (WINAPI *pLookupAccountSid)(LPCTSTR lpSystemName, PSID lpSid, LPTSTR lpName, LPDWORD cchName,
							 LPTSTR lpReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
BOOL (WINAPI *pOpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);

/* Psapi.dll: */
BOOL (WINAPI *pEnumProcesses)(DWORD *pProcessIds, DWORD cb, DWORD *pBytesReturned);


/* Since this is C and bool is technically a C++ type... */
typedef int bool;

#define false 0
#define true -1

/* Global variables */
char *userstring, *newuserstring, *rserver, *rdb, *ruser, *rpassword, *rlogserver;
SERVICE_STATUS_HANDLE hStatus;
SERVICE_STATUS ServiceStatus;
struct sockaddr_in syslogaddr;
WSADATA wsa;
bool amservice, ssl, rssl;
double osversion;
int rport, rlogport, rlog;
SOCKET sock;

/* And let's begin... */

/* At a glance: if the "debug" parameter is true then we won't send the information to syslog
 *				if "e" is 0 then we won't try to look up an error message for it
 */
void Log(bool debug, char *msg, const DWORD e)
{
	char *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	char *out, *official, *machine, *mac, *buf;
	PIP_ADAPTER_INFO adap, padap;
	LPTSTR lpMsgBuf = NULL;
	struct tm *today;
	int pri, i;
	time_t now;
	DWORD sz;
	FILE *fh;

	if (rlog == 0) /* Don't even waste our breathe */
		return;

	/* Try to retrieve the text version of an error message */
	if (e != 0)
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, e, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);

	/* Make a buffer that is large enough */
	sz = strlen(msg) + 32;
	if (lpMsgBuf)
		sz += strlen(lpMsgBuf);
	out = (char *)malloc(sz);

	/* Only print the message if we don't have an error code */
	if (e == 0)
		strcpy(out, msg);
	/* Print text error message if we have one */
	else if (lpMsgBuf)
	{
		/* Kill any newline characters */
		buf = lpMsgBuf;
		while (*buf++)
			if ((*buf == '\r') || (*buf == '\n'))
				*buf = 0;

		sprintf(out, "%s: (Error: 0x%x) %s", msg, e, lpMsgBuf);
		LocalFree(lpMsgBuf);
	}
	/* Tell the user he has to figure it out, we tried */
	else
		sprintf(out, "%s: (unknown error code 0x%x)", msg, e);

	/* Get the current system time */
	time(&now);
	today = localtime(&now);

	/* Get the machine name */
	sz = 64;
	machine = (char *)malloc(sz);
	GetComputerName(machine, &sz);

	/* Set priority */
	if (debug)
		pri = (4 * 8) + 7; /* Security + Debug == local only */
	else
		pri = (4 * 8) + 5; /* Security + Notice == local and remote */

	/* Format the "official" syslog message */
	official = (char *)malloc(1024);
	sprintf(official, "<%2i>%s %2i %02i:%02i:%02i %s " SERVICENAME ": ", pri, month[today->tm_mon],
			today->tm_mday, today->tm_hour, today->tm_min, today->tm_sec, machine);
	free(machine);

	/* Truncate to 1024 (1022 + \r\n) characters, if necessary */
	if (strlen(official) + strlen(out) > 1022)
		out[1022 - strlen(official)] = 0;

	/* Continue by adding on the message buffer */
	strcat(official, out);

	/* If logging to a file is enabled */
	if ((rlog & 0x1) && (!amservice))
	{
		fh = fopen(SERVICENAME ".txt", "a");
		fprintf(fh, "%s\r\n", official);
		fclose(fh);
	}

	/* If logging to syslog is enabled */
	if ((rlog & 0x2) && (!debug))
	{
		/* Open a socket if necessary */
		if (sock == 0)
			if (!(sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)))
				Log(true, "Failed to open socket to syslog server", WSAGetLastError());

		/* Find out how much space we need for network IP/MAC information */
		sz = 0;
		GetAdaptersInfo(NULL, &sz);

		/* Allocate it */
		adap = (IP_ADAPTER_INFO *)malloc(sz);

		/* Get network information */
		GetAdaptersInfo(adap, &sz);

		sz = strlen(official) + 2;
		if (sz < 1021)
			strcat(official, " (");

		/* Make a pointer, and loop through the interfaces */
		padap = adap;
		do
		{
			/* Get the MAC address */
			mac = (char *)malloc(65); /* column size + 1 */
			buf = (char *)malloc(4);  /* temporary buffer */
			*mac = 0;

			for (i = 0; i < (padap->AddressLength - 1); i++)
			{
				sprintf(buf, "%.2X-", (int)padap->Address[i]);
				strcat(mac, buf);
			}
			sprintf(buf, "%.2X", (int)padap->Address[i]);
			strcat(mac, buf);
			free(buf);

			sz += strlen(mac);
			if (sz < 1021)
				strcat(official, mac);
			free(mac);

			/* Report the IP address too */
			if ((strcmp(padap->IpAddressList.IpAddress.String, "0.0.0.0") != 0) &&
				(strncmp(padap->IpAddressList.IpAddress.String, "169.", 4) != 0))
			{
				if (++sz < 1021)
					strcat(official, "/");
				sz += strlen(padap->IpAddressList.IpAddress.String);
				if (sz < 1021)
					strcat(official, padap->IpAddressList.IpAddress.String);
			}

			padap = padap->Next;
			if (padap)
				if (++sz < 1021)
					strcat(official, ";");
		} while (padap);

		if (++sz < 1021)
			strcat(official, ")");

		/* Send the message */
		if (sock != 0)
			sendto(sock, official, strlen(official), 0, (SOCKADDR *)&syslogaddr, sizeof(syslogaddr));
	}

	free(official);
	free(out);

	return;
}

int install(char *location)
{
	SC_HANDLE scm, service;
	LPTSTR lpFilename;
	int ret = 0;
	DWORD dw = 0;
	HKEY hkey;
	long val;

	lpFilename = (char *)malloc(MAX_PATH * sizeof(char));
	if (!GetModuleFileName(NULL, lpFilename, MAX_PATH))
	{
		Log(true, "Can not find program path", GetLastError());
		free(lpFilename);
		return 1;
	}

	if (osversion >= 5)
	{
		Log(true, "Installing service...", 0);

		/* open a connection to the SCM */
		scm = pOpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
		if (!scm)
		{
			Log(true, "Error connecting to local Service Control Manager (SCM)", GetLastError());
			free(lpFilename);
			return 2;
		}
	    
		/* Install ourselves as a service */
		service = pCreateService(scm, SERVICENAME, SERVICENAME, SERVICE_ALL_ACCESS,
									SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
									SERVICE_ERROR_NORMAL, lpFilename, 0, 0, 0, 0, 0);
		if (!service)
		{
			Log(true, "Error creating a new service", GetLastError());
			ret = 3;
		}
		else
			pCloseServiceHandle(service);
   
		pCloseServiceHandle(scm);
	}
	/* Install as a regular program for Windows 98 or ME */
	else
	{
		Log(true, "Installing startup program...", 0);

		if (val = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
						0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &dw))
		{
			Log(true, "Error creating registry key", val);
			return 6;
		}

		RegSetValueEx(hkey, SERVICENAME, 0, REG_SZ, (LPBYTE)lpFilename, strlen(lpFilename) + 1);

		RegCloseKey(hkey);
	}

	free(lpFilename);

	return ret;
}

int uninstall()
{
	SC_HANDLE service, scm;
	BOOL success;
	SERVICE_STATUS status;
	int ret = 0;
	DWORD dw = 0;
	HKEY hkey;
	long val;

	/* Remove ourselves as a service on Windows 2000 or above */
	if (osversion >= 5)
	{
		/* Let's tell syslog when we are uninstalled */
		Log(false, "Removing service...", 0);

		/* Open a connection to the SCM */
		scm = pOpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
		if (!scm)
		{
			Log(true, "Error connecting to local Service Control Manager (SCM)", GetLastError());
			return 2;
		}
	    
		/* Get our service's handle */
		service = pOpenService(scm, SERVICENAME, SERVICE_ALL_ACCESS | DELETE);
		if (!service)
		{
			Log(true, "Error openning new service", GetLastError());
			ret = 4;
		}
  
		/* Stop the service if it is running */
		success = pQueryServiceStatus(service, &status);
		if (!success)
			Log(true, "Error reading service status", GetLastError());
		if (status.dwCurrentState != SERVICE_STOPPED)
		{
			success = pControlService(service, SERVICE_CONTROL_STOP, &status);
			if (!success)
				Log(true, "Error while trying to stop service", GetLastError());

			/* We shouldn't be doing anything that takes a while to stop doing, but
			 * try to notify the user. */
			//printf("Waiting %i seconds to give %s a chance to stop.\n", SLEEPTIME / 1000, SERVICENAME);
			Sleep(SLEEPTIME);
		}
  
		/* Remove the service */
		success = pDeleteService(service);
		if (!success)
			Log(true, "Error deleting service", GetLastError());
  
		/* Clean up */
		pCloseServiceHandle(service);
		pCloseServiceHandle(scm);
	}
	/* Remove ourselves from being a startup program on Windows 98 and ME */
	else
	{
		Log(false, "Removing startup program...", 0);

		if (val = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
						0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &dw))
		{
			Log(true, "Error creating registry key", val);
			return 6;
		}

		RegDeleteValue(hkey, SERVICENAME);

		RegCloseKey(hkey);
	}

	return ret;
}

/* Loosely based off of Microsoft's example for encrypting a file */
char *EncryptString(char *password, char *text)
{
	char *ptr, *ptr2, *buf, *ret = NULL;
	HCRYPTPROV hKey, hXchgKey, hHash, hCryptProv;
	PBYTE pbBuffer, pbKeyBlob;
	DWORD dwBlockLen, dwBufferLen, dwCount;
	int pos;

	/* Self-explanatory if you seen the GDI functions */
	if (!CryptAcquireContext(&hCryptProv, "Container", NULL, PROV_RSA_FULL, 0))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContext(&hCryptProv, "Container", NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				Log(true, "Error in call to CryptAcquireContext() after receiving NTE_BAD_KEYSET", GetLastError());
				return NULL;
			}
		}
		else
		{
			Log(true, "Error in call to CryptAcquireContext()", GetLastError());
			return NULL;
		}
	}

	/* Create an SHA-1 hash */
	if (!CryptCreateHash(hCryptProv, CALG_SHA, 0, 0, &hHash))
	{
		Log(true, "Error in call to CryptCreateHash()", GetLastError());
		CryptReleaseContext(hCryptProv, 0);
		return NULL;
	}

	/* Hash our password */
	if (!CryptHashData(hHash, (BYTE *)password, lstrlen(password), 0))
	{
		Log(true, "Error in call to CryptHashData()", GetLastError());
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		return NULL;
	}

	/* Get a session key... Some version of Windows was always complaining
	 * about the next-to-last parameter. Null lets Windows decide, I guess.
	 * Kudos to some guys on a Chinese (or Japanese? I don't speak either
	 * language and they use the same characters) forum for knowing that. */
	if (!CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, 0x0, &hKey))
	{
		Log(true, "Error in call to CryptDeriveKey()", GetLastError());
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		return NULL;
	}

	/* Determine the number of bytes to encrypt at a time. */
	dwBlockLen = 1000 - (1000 % ENCRYPT_BLOCK_SIZE);

	/* If a block cipher is used, it must have room for an extra block. */
	dwBufferLen = dwBlockLen;
	if (!CryptEncrypt(hKey, (HCRYPTHASH)NULL, true, 0, NULL, &dwBufferLen, 0))
	{
		Log(true, "Error getting encryption buffer length", 0);
		return NULL;
	}
	
	pbBuffer = (BYTE *)malloc(dwBufferLen);
	ret = (char *)malloc(1);
	buf = (char *)malloc(3);
	ptr = text;
	*ret = 0;

	do
	{
		strncpy(pbBuffer, ptr, dwBlockLen);
		dwCount = strlen(pbBuffer);
		ptr += dwCount;

		/* And... action. */
		if (!CryptEncrypt(hKey, (HCRYPTHASH)NULL, (dwCount == dwBlockLen), 0, pbBuffer, &dwCount, dwBufferLen))
		{
			Log(true, "Error in call to CryptEncrypt()", GetLastError());
			break;
		}

		/* Turn the encrypted data into a hexadecimal string for storage */
		ret = (char *)realloc(ret, strlen(ret) + (dwCount * 2) + 1);
		pos = -1;
		while (++pos < dwCount)
		{
			sprintf(buf, "%2X", *(pbBuffer + pos));
			strcat(ret, buf);
		}
	} while (dwCount == dwBlockLen);

	/* Clean up */
	free(buf);
	free(pbBuffer);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hCryptProv, 0);
	
	return ret;
}

/* Heavily based off the function above */
char *DecryptString(char *password, char *hash)
{
	char *ptr, *ptr2, *buf, *ret = NULL;
	HCRYPTPROV hKey, hXchgKey, hHash, hCryptProv;
	PBYTE pbBuffer, pbKeyBlob;
	DWORD dwBlockLen, dwBufferLen, dwCount;
	int pos;

	/* Self-explanatory if you seen the GDI functions */
	if (!CryptAcquireContext(&hCryptProv, "Container", NULL, PROV_RSA_FULL, 0))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContext(&hCryptProv, "Container", NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				Log(true, "Error in call to CryptAcquireContext() after receiving NTE_BAD_KEYSET", GetLastError());
				return NULL;
			}
		}
		else
		{
			Log(true, "Error in call to CryptAcquireContext()", GetLastError());
			return NULL;
		}
	}

	if (!CryptCreateHash(hCryptProv, CALG_SHA, 0, 0, &hHash))
	{
		Log(true, "Error in call to CryptCreateHash()", GetLastError());
		CryptReleaseContext(hCryptProv, 0);
		return NULL;
	}

	/* Hash our password */
	if (!CryptHashData(hHash, (BYTE *)password, lstrlen(password), 0))
	{
		Log(true, "Error in call to CryptHashData()", GetLastError());
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		return NULL;
	}

	/* Get a session key */
	if (!CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, 0x0, &hKey))
	{
		Log(true, "Error in call to CryptDeriveKey()", GetLastError());
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		return NULL;
	}

	/* Determine the number of bytes to encrypt at a time. */
	dwBlockLen = 1000 - (1000 % ENCRYPT_BLOCK_SIZE);

	/* If a block cipher is used, it must have room for an extra block. */
	dwBufferLen = dwBlockLen;
	
	pbBuffer = (BYTE *)malloc(dwBufferLen * 2 + 1);
	pbBuffer[dwBufferLen * 2] = 0; /* Null-pad since strncpy() does not always */
	ret = (char *)malloc(1);
	buf = (char *)malloc(3);
	ptr = hash;
	*ret = 0;

	do
	{
		strncpy(pbBuffer, ptr, dwBlockLen * 2);
		dwCount = strlen(pbBuffer);
		ptr += dwCount;

		/* Turn the hexadecimal string into the encrypted string
		 * Bad pun: We're going to dehex the password. */
		pos = -1;
		*(buf + 2) = 0;
		while (++pos < dwCount)
		{
			/* Copy one character in hex form */
			*buf = *(pbBuffer + (pos * 2));
			*(buf + 1) = *(pbBuffer + (pos * 2) + 1);

			/* We're copying the data back to the active buffer (since it is smaller than what
			 * we are converting)... probably a bad practice, but we're doing it safely. */
			*(pbBuffer + pos) = strtol(buf, NULL, 16);
		}
		*(pbBuffer + pos) = 0;
		dwCount /= 2; /* Hex->Bytes */

		/* And... action. */
		if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, (dwCount == dwBlockLen), 0, pbBuffer, &dwCount))
		{
			Log(true, "Error in call to CryptDecrypt()", GetLastError());
			break;
		}

		ret = (char *)realloc(ret, strlen(ret) + dwCount + 1);
		strcat(ret, pbBuffer);
	} while (dwCount >= dwBlockLen);

	/* Clean up */
	free(buf);
	free(pbBuffer);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hCryptProv, 0);
	
	return ret;
}

/* Check if the specified domain\user combination has been found already. If
 * not then add it to the user string
 */
void AppendUser(char *user, char *domain)
{
	char *buf, *ptr;
	int len;
	bool found;

	/* Turn the domain/username into a string for the database */
	len = strlen(domain) + strlen(user) + 3;
	buf = (char *)malloc(len * sizeof(char));
	sprintf(buf, "%s\\%s;", domain, user);

	/* Look to see if the username already exists in our list */
	found = false;
	ptr = newuserstring;
	if (strncmp(ptr, buf, strlen(buf)) == 0)
		found = true;

	while ((!found) && (ptr = strstr(ptr, ";")))
		if (strncmp(++ptr, buf, strlen(buf)) == 0)
			found = true;

	/* if it doesn't */
	if (!found)
	{
		newuserstring = (char *)realloc(newuserstring, (strlen(newuserstring) + strlen(buf) + 1) * sizeof(char));
		strcat(newuserstring, buf);
	}

	free(buf);

	return;
}

/* This function connects to a MySQL database and sends userstring, which
 * contains the active (and possibly logged in, but inactive) user(s). It
 * also detects current IP and MAC addresses to send along.
 */
void UpdateMysql()
{
	char *buf, *ptr, *escaped, *mac, *ip, *machine;
	PIP_ADAPTER_INFO adap, padap;
	unsigned int i;
	MYSQL mysql;
	FILE *fh;
	DWORD sz;

	/* MySQL requires the key/certificate to be in files... */
	if ((rssl) && (!ssl))
	{
		fh = fopen(SERVICENAME "-key.pem", "w");
		fwrite(KEY, 1, strlen(KEY), fh);
		fclose(fh);

		fh = fopen(SERVICENAME "-cert.pem", "w");
		fwrite(CERT, 1, strlen(CERT), fh);
		fclose(fh);

		ssl = true;
	}

	mysql_init(&mysql);

	if (ssl)
		mysql_ssl_set(&mysql, SERVICENAME "-key.pem", SERVICENAME "-cert.pem", NULL, NULL /*capath*/, NULL);

	/* Unfortunately we have to make the password plain-text here... */
	if (!(ptr = DecryptString(NCRYPTPSWD, rpassword)))
	{
		Log(true, "Error decrypting password. Received NULL.", 0);
		mysql_close(&mysql);
		return;
	}

	if (!mysql_real_connect(&mysql, rserver, ruser, ptr, rdb, rport, NULL, 0))
	{
		if (!amservice)
		{
			buf = (char *)malloc(1024);
			/* It's a bad idea to send the decrypted password anywhere... use with caution */
			//sprintf(buf, "mysql_real_connect(&mysql, \"%s\", \"%s\", \"%s\", \"%s\", %i, NULL, 0)", rserver, ruser, ptr, rdb, rport);
			//Log(true, buf, 0);
			sprintf(buf, "Unable to connect to database: %s", mysql_error(&mysql));
			Log(false, buf, 0);
			free(buf);
		}
		free(ptr);
		mysql_close(&mysql);
		return;
	}

	free(ptr);
	escaped = (char *)malloc((strlen(userstring) * 2) + 1);
	mysql_real_escape_string(&mysql, escaped, userstring, strlen(userstring));

	/* Report the machine name; it can be up to 63 characters long */
	sz = 64;
	machine = (char *)malloc(sz);
	GetComputerName(machine, &sz);

	/* Find out how much space we need for network IP/MAC information */
	sz = 0;
	GetAdaptersInfo(NULL, &sz);

	/* Allocate it */
	adap = (IP_ADAPTER_INFO *)malloc(sz);

	/* Get network information */
	GetAdaptersInfo(adap, &sz);

	/* Allocate some more memory */
	mac = (char *)malloc(65); /* column size + 1 */

	/* Make a pointer, and loop through the interfaces */
	padap = adap;
	do
	{
		/* Get the MAC address */
		buf = (char *)malloc(4);  /* temporary buffer */
		*mac = 0;

		for (i = 0; i < (padap->AddressLength - 1); i++)
		{
			sprintf(buf, "%.2X-", (int)padap->Address[i]);
			strcat(mac, buf);
		}
		sprintf(buf, "%.2X", (int)padap->Address[i]);
		strcat(mac, buf);
		free(buf);

		/* Report the MAC and IP address along with the computer name */
		ip = padap->IpAddressList.IpAddress.String;
		if ((strcmp(ip, "0.0.0.0") != 0) &&
			(strncmp(ip, "169.", 4) != 0))
		{
			ptr = "INSERT INTO usermap (users, mac, ip, compname) VALUES ('%s', '%s', '%s', '%s') "
				  "ON DUPLICATE KEY UPDATE users = '%s', ip = '%s', compname = '%s', updated = NOW()";
			buf = (char *)malloc(strlen(ptr) + strlen(escaped) * 2 + strlen(mac) + strlen(ip) * 2 + strlen(machine) * 2);
			sprintf(buf, ptr, escaped, mac, ip, machine, escaped, ip, machine);
			if (mysql_query(&mysql, buf))
				Log(true, mysql_error(&mysql), 0);

			free(buf);
		}

		padap = padap->Next;
	} while (padap);

	mysql_close(&mysql);
	free(machine);
	free(escaped);
	free(adap);
	free(mac);

	return;
}

/* There are several ways to find out which users are logged in. None of them
 * works 100%, so we're going to use a hack that involves enumerating the
 * running programs, and then determining the user running each one. Duplicates
 * and system names will be removed.
 *
 * For fun, here are some of the methods others use and why they don't work:
 *
 * 1. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 *	- No longer works on Vista.
 *	- It shows the user with the highest credentials only.
 * 2. Enumerating HKEY_USERS\*\Volatile Environment
 *	- On 2K/XP, this shows which users have logged on since the last reboot.
 * 3. LsaEnumerateLogonSessions()
 *	- Rumored to work on XP and up (so we converted this program to unicode to support it)
 *	- It can be confused.
 *	- Log on to an account, launch program, switch users, launch program,
 *	  switch back, close program, logout, switch again, close program, logout.
 *	- XP (at least) will from then on always say one of those users is logged on.
 * 4. WTSEnumerateSessions()
 *	- Only works if the Terminal Server service is running.
 *	- Haven't tested this one, there was no reason to.
 * 5. NetWkstaUserGetInfo()
 *	- Looks promising at first, but must be called in the user's context.
 *
 * An additional note about the method we *are* using. 
 *	- GetTokenInformation() always seems to return "Administrator" when asked
 *	  for TokenOwner on Windows 2000. TokenUser returns the right information.
 */
void LogUserName(bool names)
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	SID_NAME_USE SidType = SidTypeUnknown;
	DWORD val, dw, sz;
	unsigned int i;
	HANDLE hp, hpt;
	char *user, *domain;
	TOKEN_USER *Owner;
	HMODULE hMod;
	HKEY hkey;
	SID *sid;
	char *olduserstring, *buf, *ptr, *ptr2;

	if (names)
	{
		user = (char *)malloc(MAXNAME * sizeof(char));
		domain = (char *)malloc(MAXNAME * sizeof(char));
		strcpy(user, "");
		strcpy(domain, "");

		/* if Windows 2000 or above */
		if (osversion >= 5)
		{
			if (!pEnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
				return;

			cProcesses = cbNeeded / sizeof(DWORD);

			for (i = 0; i < cProcesses; i++)
			{
				if (aProcesses[i] != 0)
				{
					hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
					if (hp != NULL)
					{
						if (!pOpenProcessToken(hp, MAXIMUM_ALLOWED, &hpt))
						{
							Log(true, "Error processing token", GetLastError());
							CloseHandle(hp);
							continue;
						}

						pGetTokenInformation(hpt, TokenUser, NULL, 0, &dw);
						if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
						{
							Log(true, "Error retrieving token size", GetLastError());
							CloseHandle(hpt);
							CloseHandle(hp);
							continue;
						}
						else
						{
							Owner = (TOKEN_USER *)malloc(sizeof(DWORD) * dw);
							if (!pGetTokenInformation(hpt, TokenUser, Owner, dw, &dw))
							{
								Log(true, "Error retrieving token owner information class data", GetLastError());
								CloseHandle(hpt);
								CloseHandle(hp);
								continue;
							}
						}
						dw = pGetLengthSid(Owner->User.Sid);
						sid = (SID *)malloc(dw);
						pCopySid(dw, sid, Owner->User.Sid);
						dw = MAXNAME;

						if (!pLookupAccountSid(NULL, sid, user, (LPDWORD)&dw, domain, (LPDWORD)&dw, &SidType))
						{
							val = GetLastError();
							if (val == ERROR_NONE_MAPPED)
								strcpy(user, "NONE_MAPPED");
							else
								Log(true, "LookupAccountSid failed", val);
						}

						free(sid);
						free(Owner);
						CloseHandle(hpt);
					}

					if ((strcmp(domain, "NT AUTHORITY") != 0) && (strcmp(domain, "WORKGROUP") != 0) &&
						(strcmp(domain, "BUILTIN") != 0) && (*domain))
							AppendUser(user, domain);

					CloseHandle(hp);
				}
			}
		}
		/* For Windows 9x... */
		else
		{
			sz = MAXNAME;
			GetUserName(user, &sz);

			if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
								"System\\CurrentControlSet\\Services\\MSNP32\\NetworkProvider",
								0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &dw) == ERROR_SUCCESS)
			{
				sz = MAXNAME;
				dw = REG_SZ;
				if (RegQueryValueEx(hkey, "AuthenticatingAgent", 0, &dw, (LPBYTE)domain, &sz) != ERROR_SUCCESS)
				{
					/* Fall back to the computer name... */
					sz = MAXNAME;
					GetComputerName(domain, &sz);
				}

				RegCloseKey(hkey);
			}
			else
			{
				/* Fall back to the computer name... */
				sz = MAXNAME;
				GetComputerName(domain, &sz);
			}

			/* If there is a user logged in... */
#pragma TODO("LogUserName(): Get Windows 9x to exit gracefully")
			if (*user)
				AppendUser(user, domain);
			/* If not... self-terminate */
			else
				ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		}

		free(user);
		free(domain);
	}

	/* Has the list of users changed? */
	if (strcmp(userstring, newuserstring) != 0)
	{
		olduserstring = userstring;
		userstring = (char *)malloc(strlen(newuserstring) + 1);
		strcpy(userstring, newuserstring);

		ptr = ptr2 = newuserstring;
		while (*++ptr)
		{
			if (*ptr == ';')
			{
				*ptr = 0;
				if (strstr(olduserstring, ptr2) == NULL)
				{
					buf = (char *)malloc(strlen(ptr2) + 11);
					sprintf(buf, "%s logged in", ptr2);
					Log(false, buf, 0);

					free(buf);
				}
				ptr2 = ptr + 1;
			}
		}

		free(newuserstring);
		newuserstring = (char *)malloc(strlen(olduserstring) + 1);
		strcpy(newuserstring, olduserstring);

		ptr = ptr2 = newuserstring;
		while (*++ptr)
		{
			if (*ptr == ';')
			{
				*ptr = 0;
				if (strstr(userstring, ptr2) == NULL)
				{
					buf = (char *)malloc(strlen(ptr2) + 12);
					sprintf(buf, "%s logged out", ptr2);
					Log(false, buf, 0);

					free(buf);
				}
				ptr2 = ptr + 1;
			}
		}

		free(olduserstring);
		free(newuserstring);

		if (rlog != -1)
			UpdateMysql();
	}
	else
		free(newuserstring);

	newuserstring = (char *)malloc(sizeof(char));
	strcpy(newuserstring, "");

	return;
}

int SetRegistryConfig(char *config)
{
	int len;
	HKEY hkey;
	DWORD dw = 0;
	long val;
	char *ptr, *ptr2;

	ptr = config;
	while (*++ptr)
	{
		if (*ptr == '=')
		{
			*ptr++ = 0;
			break;
		}
	}

	if (*ptr == 0)
	{
		Log(true, "Error: No value supplied for configuration option", 0);
		return 5;
	}
	else if (strlen(ptr) > 127)
	{
		Log(true, "Warning: Please keep setting values to less than 127 characters", 0);
		*(ptr + 127) = 0;
	}

	/* lets encrypt password, just in case somebody goes registry diving */
	if (strcmp(config, "password") == 0)
	{
		ptr2 = EncryptString(NCRYPTPSWD, ptr);
		free(ptr);
		if (ptr2 != NULL)
			ptr = ptr2;
		else
			return 7;
	}

	if (val = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\" SERVICENAME, 0, NULL,
						REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &dw))
	{
		Log(true, "Error creating registry key", val);
		return 6;
	}

	/* DWORD (numerical) values */
	if ((strcmp(config, "port") == 0) || (strcmp(config, "log") == 0) ||
		(strcmp(config, "logport") == 0) || (strcmp(config, "ssl") == 0))
	{
		dw = atoi(ptr);
		RegSetValueEx(hkey, config, 0, REG_DWORD, (const BYTE *)&dw, sizeof(DWORD));
	}
	/* Otherwise use a string */
	else
		RegSetValueEx(hkey, config, 0, REG_SZ, (LPBYTE)ptr, strlen(ptr) + 1);

	RegCloseKey(hkey);

	return 0;
}

char *GetConfigString(char *config)
{
	int len;
	HKEY hkey;
	DWORD sz, dw = 0;
	long val;
	char *ptr, *ret;

	/* Default return value */
	if (strcmp(config, "server") == 0)
		ptr = SQLSERVER;
	else if (strcmp(config, "db") == 0)
		ptr = SQLDB;
	else if (strcmp(config, "user") == 0)
		ptr = SQLUSER;
	else if (strcmp(config, "password") == 0)
		ptr = SQLPASS;
	else if (strcmp(config, "logserver") == 0)
		ptr = LOGSERVER;
	/* if we don't know what they are asking for */
	else
	{
		ret = (char *)malloc(sizeof(char));
		strcpy(ret, "");
		return ret;
	}

	ret = (char *)malloc((strlen(ptr) + 1) * sizeof(char));
	strcpy(ret, ptr);

	if (val = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\" SERVICENAME, 0, NULL,
						REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &dw))
	{
		Log(true, "Error creating registry key", val);
		return ret;
	}

	sz = 128;
	dw = REG_SZ;
	ptr = (char *)malloc(sz * sizeof(char));
	if (RegQueryValueEx(hkey, config, 0, &dw, (LPBYTE)ptr, &sz) == ERROR_SUCCESS)
	{
		free(ret);
		*(ptr + sz) = 0;
		ret = (char *)realloc(ptr, sz + 1);
	}
	else
		free(ptr);

	RegCloseKey(hkey);

	return ret;
}

int GetConfigNum(char *config)
{
	int ret = 0;
	HKEY hkey;
	DWORD sz, dw = 0;
	long val;

	if (strcmp(config, "log") == 0)
		ret = LOG;
	else if (strcmp(config, "port") == 0)
		ret = SQLPORT;
	else if (strcmp(config, "logport") == 0)
		ret = LOGPORT;
	else if (strcmp(config, "ssl") == 0)
		ret = SQLSSL;
	/* if the programmer didn't ask correctly... */
	else
		return ret;

	if (val = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\" SERVICENAME, 0, NULL,
						REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &dw))
	{
		Log(true, "Error creating registry key", val);
		return ret;
	}

	sz = sizeof(DWORD);
	if (RegQueryValueEx(hkey, config, 0, &dw, (LPBYTE)&ret, &sz) != ERROR_SUCCESS)
	{
		if (strcmp(config, "port") == 0)
			ret = SQLPORT;
		else if (strcmp(config, "logport") == 0)
			ret = LOGPORT;
		else if (strcmp(config, "ssl") == 0)
			ret = SQLSSL;
		else
			ret = LOG;
	}

	RegCloseKey(hkey);

	return ret;
}

/* React to service stop/shutdown commands */
void ControlHandler(DWORD request)
{
	if ((request == SERVICE_CONTROL_STOP) || (request == SERVICE_CONTROL_SHUTDOWN))
	{
		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	}

	/* Report current status */
	SetServiceStatus(hStatus, &ServiceStatus);

	return;
}

void ServiceMain(int argc, char** argv)
{
	int result = 0;
	MSG msg;
	FILE *fh;

	ServiceStatus.dwServiceType        = SERVICE_WIN32;
	ServiceStatus.dwCurrentState       = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode      = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint         = 0;
	ServiceStatus.dwWaitHint           = 0;

	if (osversion >= 5)
	{
		hStatus = RegisterServiceCtrlHandler(SERVICENAME, (LPHANDLER_FUNCTION)ControlHandler); 
		if (hStatus == (SERVICE_STATUS_HANDLE)0)
				return;
	}

	/* Report the running status to SCM. */
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	if (osversion >= 5)
		SetServiceStatus(hStatus, &ServiceStatus);

	Log(false, "Service started...", 0);

	/* Loop until we are supposed to quit */
	while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		/* Check which user is logged in and send status to central server */
		LogUserName(true);

		Sleep(SLEEPTIME);

		/* Try to detect the user shutting down in Windows 9x */
		if (osversion < 5)
		{
			while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
			{
				TranslateMessage(&msg);
				if (msg.message == WM_QUIT)
				{
					PostQuitMessage(0);
					ServiceStatus.dwCurrentState = SERVICE_STOPPED;
				}
			}
		}
	}

	return;
}

int main_from_winmain(int argc, char *argv[])
{
	SERVICE_TABLE_ENTRY ServiceTable[2];
	OSVERSIONINFO osv;
	HOSTENT *host;
	int x, ret = 0;
	char *ptr;

	/* Basic initializations */
	amservice = true;
	ssl = false;
	sock = 0;

	ZeroMemory(&osv, sizeof(OSVERSIONINFO));
	osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osv);

	/* Let's turn the OS version into a decimal number. */
	osversion = osv.dwMinorVersion;
	while (osversion >= 1)
		osversion /= 10;
	osversion += osv.dwMajorVersion;

	/* Initialize the socket interface */
	WSAStartup(MAKEWORD(1, 1), &wsa);

	/* Let's grab these here so we know what to log */
	rlog = GetConfigNum("log");
	rlogport = GetConfigNum("logport");
	rlogserver = GetConfigString("logserver");
	/* No error message, just in case the user is trying to disable logging
	 * and we haven't checked the switches yet */
	if ((host = gethostbyname(rlogserver)) != NULL)
		syslogaddr.sin_addr.S_un.S_addr = ((struct in_addr *)*host->h_addr_list)->s_addr;
	syslogaddr.sin_family = AF_INET;
	syslogaddr.sin_port = htons(rlogport);

	pOpenSCManager = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "OpenSCManagerA");
	pCreateService = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "CreateServiceA");
	pOpenService = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "OpenServiceA");
	pCloseServiceHandle = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "CloseServiceHandle");
	pQueryServiceStatus = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "QueryServiceStatus");
	pDeleteService = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "DeleteService");
	pControlService = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "ControlService");
	pSetServiceStatus = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "SetServiceStatus");
	pGetTokenInformation = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "GetTokenInformation");
	pGetLengthSid = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "GetLengthSid");
	pCopySid = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "CopySid");
	pLookupAccountSid = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "LookupAccountSidA");
	pOpenProcessToken = (PVOID)GetProcAddress(LoadLibrary("Advapi32.dll"), "OpenProcessToken");
	pEnumProcesses = (PVOID)GetProcAddress(LoadLibrary("Psapi.dll"), "EnumProcesses");

	newuserstring = (char *)malloc(sizeof(char));
	userstring = (char *)malloc(2 * sizeof(char));
	strcpy(newuserstring, "");
	strcpy(userstring, "/"); /* force update on start -- even if there are no users logged on */

	/* Process command line arguments */
	if (argc > 1)
	{
		amservice = false;
		for (x = 1; x < argc; x++)
		{
			/* Don't log if we are disabling logging to a file... */
#pragma TODO("main_from_winmain(): Clear this when we figure out why parameters are sometimes truncated")
			if ((strcmp(argv[x], "/log=0") == 0) || (strcmp(argv[x], "/log=2") == 0))
				Log(true, argv[x], 0);

			/* Lets make the argument lower-case, stop if we encounter an '=' sign */
			ptr = argv[x];
			while ((*ptr++) && (*ptr != '='))
				if ((*ptr >= 'A') && (*ptr <= 'Z'))
					*ptr |= 0x20;

			/* now compare it */
			if (strcmp(argv[x], "/install") == 0)
				ret = install(argv[0]);
			else if (strcmp(argv[x], "/uninstall") == 0)
				ret = uninstall();
			else if (strncmp(argv[x], "/server=", 8) == 0)
				ret = SetRegistryConfig(argv[x] + 1);
			else if (strncmp(argv[x], "/db=", 4) == 0)
				ret = SetRegistryConfig(argv[x] + 1);
			else if (strncmp(argv[x], "/port=", 6) == 0)
				ret = SetRegistryConfig(argv[x] + 1);
			else if (strncmp(argv[x], "/user=", 6) == 0)
				ret = SetRegistryConfig(argv[x] + 1);
			else if (strncmp(argv[x], "/password=", 10) == 0)
				ret = SetRegistryConfig(argv[x] + 1);
			else if (strncmp(argv[x], "/ssl=", 5) == 0)
				ret = SetRegistryConfig(argv[x] + 1);
			else if (strncmp(argv[x], "/logserver=", 11) == 0)
			{
				ret = SetRegistryConfig(argv[x] + 1);
				free(rlogserver);

				rlogserver = GetConfigString("logserver");
				if ((host = gethostbyname(rlogserver)) == NULL)
					Log(true, "Error resolving syslog server (you will not be warned on future starts)", WSAGetLastError());
				else
					syslogaddr.sin_addr.S_un.S_addr = *host->h_addr_list[0];

				if (sock != 0)
				{
					closesocket(sock);
					sock = 0;
				}
			}
			else if (strncmp(argv[x], "/logport=", 9) == 0)
			{
				ret = SetRegistryConfig(argv[x] + 1);
				rlogport = GetConfigNum("logport");
				syslogaddr.sin_port = htons(rlogport);

				if (sock != 0)
				{
					closesocket(sock);
					sock = 0;
				}
			}
			else if (strncmp(argv[x], "/log=", 5) == 0)
			{
				ret = SetRegistryConfig(argv[x] + 1);
				rlog = GetConfigNum("log");
			}
			else if (strcmp(argv[x], "/test") == 0)
			{
				rserver = GetConfigString("server");
				rport = GetConfigNum("port");
				rdb = GetConfigString("db");
				ruser = GetConfigString("user");
				rpassword = GetConfigString("password");
				rssl = GetConfigNum("ssl");

				LogUserName(true);

				free(rserver);
				free(rdb);
				free(ruser);
				free(rpassword);
			}
		}
	}
	/* Normal startup */
	else
	{
		rserver = GetConfigString("server");
		rport = GetConfigNum("port");
		rdb = GetConfigString("db");
		ruser = GetConfigString("user");
		rpassword = GetConfigString("password");
		rssl = GetConfigNum("ssl");

		if (osversion >= 5)
		{
			ServiceTable[0].lpServiceName = SERVICENAME;
			ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

			ServiceTable[1].lpServiceName = NULL;
			ServiceTable[1].lpServiceProc = NULL;

			/* Start the control dispatcher thread for our service */
			StartServiceCtrlDispatcher(ServiceTable);
		}
		else
			ServiceMain(0, NULL);

		/* Clear logged in users when we are shut down */
		LogUserName(false);

		Log(false, "Service stopped", 0);

		free(rserver);
		free(rdb);
		free(ruser);
		free(rpassword);
	}

	if (sock != 0)
		closesocket(sock);
	WSACleanup();

	free(newuserstring);
	free(userstring);
	free(rlogserver);

	if (ssl)
	{
		_unlink(SERVICENAME "-key.pem");
		_unlink(SERVICENAME "-cert.pem");
	}

	return ret;
}

/* Quick function to make this a "Windows app" for the sake of Windows 9x. */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	int ret, argc = 0;
	char **argv, *ptr;

	argv = (char **)malloc(sizeof(char *) * 2);
	argv[argc++] = "ignored";
	if (*lpCmdLine)
		argv[argc++] = lpCmdLine;

	ptr = lpCmdLine - 1;
	while (*++ptr)
	{
		if ((*(ptr) == ' ') && (*(ptr + 1) == '/'))
		{
			*ptr++ = 0;
			argv = (char **)realloc(argv, sizeof(char *) * (argc + 1));
			argv[argc++] = ptr;
		}
	}

	ret = main_from_winmain(argc, argv);

	free(argv);

	return ret;
}

