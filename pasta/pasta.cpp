// pasta.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include <stdlib.h>
#include "getopt.h"

#define MAX_RSA_KEY_LENGTH (4096)
#define MAX_README_LENGTH (8192)
#define MAX_README_KEY_LENGTH (4096)
#define MAX_README_TAIL_LENGTH (256)

const char* README_KEY_SUBSTR = "\r\nKEY:";
const char* README_TAIL_SUBSTR = "\r\nTAIL:";

void PrintError(const char* funcName) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); 

	if (FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&lpMsgBuf,
		0, NULL)) {
		fprintf(stderr, "%s failed with error %d: %s\n", funcName, dw, (char *)lpMsgBuf);
	}
}

BOOL GetReadmeFilePath(const char* encryptedPath, char* readmePath)
{
	return snprintf(readmePath, MAX_PATH, "%s_readme", encryptedPath) < MAX_PATH;
}

BOOL GetValueFromReadme(const char* readmeContents, const char* valueName, BYTE* value, DWORD* valueLength)
{
	const char* foundValue = NULL;
	const char* foundValueEnd = NULL;
	size_t foundValueLength = 0;

	foundValue = strstr(readmeContents, valueName);
	if (!foundValue)
	{
		fprintf(stderr, "failed to find %s in readme\n", valueName);
		return FALSE;
	}
	foundValue += strlen(valueName);

	foundValueEnd = strstr(foundValue, "\r\n\r\n");
	// TODO: probably a cleaner way to do this
	if (!foundValueEnd)
	{
		foundValueEnd = strchr(foundValue, '\0');
	}

	foundValueLength = (size_t)(foundValueEnd - foundValue);
	if (foundValueLength > *valueLength)
	{
		fprintf(stderr, "not enough space to store value of %s\n", valueName);
		return FALSE;
	}
	*valueLength = foundValueLength;

	if (!CryptStringToBinaryA(foundValue, foundValueLength, CRYPT_STRING_BASE64, value, valueLength, NULL, NULL))
	{
		fprintf(stderr, "failed to decode base64 for %s\n", valueName);
		return FALSE;
	}

	return TRUE;
}

BOOL GetKeyAndTailFromReadme(const char* readmePath, BYTE* key, DWORD* keyLength, BYTE* tail, DWORD* tailLength)
{
	BOOL success = FALSE;
	HANDLE readmeFile = INVALID_HANDLE_VALUE;
	// This is ugly, but the readme files shouldn't vary in size that much.
	char readmeContents[MAX_README_LENGTH + 1] = { 0 };
	DWORD actualRead = 0;

	readmeFile = CreateFileA(readmePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (readmeFile == INVALID_HANDLE_VALUE)
	{
		PrintError("CreateFileA for readme");
		goto cleanup;
	}

	if (!ReadFile(readmeFile, readmeContents, MAX_README_LENGTH, &actualRead, NULL))
	{
		PrintError("ReadFile of readme");
		goto cleanup;
	}

	if (actualRead >= MAX_README_KEY_LENGTH)
	{
		fprintf(stderr, "readme file is too long\n");
		goto cleanup;
	}

	if (!GetValueFromReadme(readmeContents, README_KEY_SUBSTR, key, keyLength))
	{
		fprintf(stderr, "failed to get key from readme\n");
		goto cleanup;
	}

	if (!GetValueFromReadme(readmeContents, README_TAIL_SUBSTR, tail, tailLength))
	{
		fprintf(stderr, "failed to get tail from readme\n");
		goto cleanup;
	}

	success = TRUE;
cleanup:
	if (readmeFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(readmeFile);
	}
	return success;
}

BOOL CreateDecryptionKey(const unsigned char* rsaKey, size_t rsaKeyLength, const unsigned char* readmeKey, size_t readmeKeyLength, HCRYPTPROV* hProv, HCRYPTKEY* hKey)
{
	BOOL success = FALSE;
	LPCTSTR containerName = TEXT("pasta decryptor key container");
	HCRYPTKEY hRsaKey = NULL;

	// either CRYPT_VERIFYCONTEXT or CRYPT_DELETEKEYSET
	if (!CryptAcquireContext(hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContext(hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
			{
				PrintError("CryptAcquireContext to create new keyset");
				goto cleanup;
			}
		}
		else
		{
			PrintError("CryptAcquireContext for default keyset");
			goto cleanup;
		}
	}

	// Delete our keyset if it already exists
	CryptAcquireContext(hProv, containerName, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_DELETEKEYSET);
	if (!CryptAcquireContext(hProv, containerName, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
	{
		PrintError("CryptAcquireContext for pasta keyset");
		goto cleanup;
	}

	if (!CryptImportKey(*hProv, rsaKey, rsaKeyLength, NULL, NULL, &hRsaKey))
	{
		PrintError("CryptImportKey for RSA key");
		goto cleanup;
	}

	if (!CryptImportKey(*hProv, readmeKey, readmeKeyLength, NULL, NULL, hKey))
	{
		PrintError("CryptImportKey for readme key");
		goto cleanup;
	}

	success = TRUE;
cleanup:
	if (!success)
	{
		if (*hProv != NULL)
		{
			CryptReleaseContext(*hProv, 0);
			*hProv = NULL;
		}
	}
	if (hRsaKey != NULL)
	{
		CryptDestroyKey(hRsaKey);
	}
	return success;
}

BOOL DecryptFileWithKeyAndTail(const char* filePath, HCRYPTKEY hKey, BYTE* tail, DWORD tailLength, BOOL force, const char* decryptedPath, BOOL* createdFile)
{
	BOOL success = FALSE;
	HANDLE encryptedFile = INVALID_HANDLE_VALUE;
	HANDLE decryptedFile = INVALID_HANDLE_VALUE;
	DWORD decryptedEndBufferLength = 0;
	DWORD actualEndBufferWrite = 0;
	BYTE endBuffer[8192] = { 0 };
	DWORD endBufferLength = 0;

	BOOL gotTimes = FALSE;
	FILETIME creationTime = { 0 };
	FILETIME accessTime = { 0 };
	FILETIME writeTime = { 0 };

	*createdFile = FALSE;

	encryptedFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (encryptedFile == INVALID_HANDLE_VALUE)
	{
		PrintError("CreateFileA for encrypted file");
		goto cleanup;
	}

	if (GetFileTime(encryptedFile, &creationTime, &accessTime, &writeTime))
	{
		gotTimes = TRUE;
	}
	else
	{
		PrintError("GetFileTime for encrypted file");
		fprintf(stderr, "WARNING: failed to get original file times -- will not restore original values\n");
	}

	// CopyFile() copies file attributes as well
	if (!CopyFileA(filePath, decryptedPath, !force))
	{
		PrintError("CopyFileA for decrypted file");
		goto cleanup;
	}
	*createdFile = TRUE;

	decryptedFile = CreateFileA(decryptedPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (decryptedFile == INVALID_HANDLE_VALUE)
	{
		PrintError("CreateFileA for decrypted file");
		goto cleanup;
	}

	if (gotTimes)
	{
		if (!SetFileTime(decryptedFile, &creationTime, &accessTime, &writeTime))
		{
			PrintError("SetFileTime for decrypted file");
			fprintf(stderr, "WARNING: failed to restore decrypted file times to original values\n");
		}
	}

	while (TRUE)
	{
		BYTE buffer[4096] = { 0 };
		DWORD actualRead = 0;
		DWORD decryptedLength = 0;
		DWORD actualWrite = 0;

		if (!ReadFile(encryptedFile, buffer, sizeof(buffer), &actualRead, NULL))
		{
			PrintError("ReadFile of encrypted file");
			goto cleanup;
		}

		// TODO: this assumes the last read is the only one that return less than requested. This might not be true!
		if (actualRead < sizeof(buffer))
		{
			memcpy(endBuffer, buffer, actualRead);
			memcpy(endBuffer + actualRead, tail, tailLength);
			endBufferLength = actualRead + tailLength;
			break;
		}

		decryptedLength = actualRead;
		if (!CryptDecrypt(hKey, NULL, FALSE, 0, buffer, &decryptedLength))
		{
			PrintError("CryptDecrypt of encrypted file");
			goto cleanup;
		}

		if (!WriteFile(decryptedFile, buffer, decryptedLength, &actualWrite, NULL))
		{
			PrintError("WriteFile of decrypted file data");
			goto cleanup;
		}
		if (decryptedLength != actualWrite)
		{
			fprintf(stderr, "bad write of %d bytes instead of %d -- aborting decryption\n", actualWrite, decryptedLength);
			goto cleanup;
		}
	}

	decryptedEndBufferLength = endBufferLength;
	if (!CryptDecrypt(hKey, NULL, TRUE, 0, endBuffer, &decryptedEndBufferLength))
	{
		fprintf(stderr, "failed to decrypt file bytes: %x", GetLastError());
		PrintError("CryptDecrypt of encrypted file");
		goto cleanup;
	}

	if (!WriteFile(decryptedFile, endBuffer, decryptedEndBufferLength, &actualEndBufferWrite, NULL))
	{
		PrintError("WriteFile of decrypted tail");
		goto cleanup;
	}
	if (decryptedEndBufferLength != actualEndBufferWrite)
	{
		fprintf(stderr, "bad tail write of %d bytes instead of %d -- aborting decryption\n", actualEndBufferWrite, decryptedEndBufferLength);
		goto cleanup;
	}

	success = TRUE;
cleanup:
	if (decryptedFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(decryptedFile);
	}
	if (encryptedFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(encryptedFile);
	}
	return success;
}

int StringEndsWith(const char* str, const char* suffix)
{
	size_t stringLength = strlen(str);
	size_t suffixLength = strlen(suffix);

	return (stringLength >= suffixLength) &&
		(0 == strcmp(str + (stringLength - suffixLength), suffix));
}

BOOL GetDecryptedFilePath(const char* encryptedPath, const char* extension, char* decryptedPath)
{
	if (!StringEndsWith(encryptedPath, extension))
	{
		fprintf(stderr, "file at %s doesn't end with encryption suffix %s -- not decrypting\n", encryptedPath, extension);
		return FALSE;
	}

	strcpy_s(decryptedPath, MAX_PATH, encryptedPath);
	PathRemoveExtensionA(decryptedPath);

	return TRUE;
}

BOOL GetRsaKeyFromFile(const char* keyBlobFile, BYTE* rsaKey, DWORD* rsaKeyLength)
{
	BOOL success = FALSE;
	HANDLE keyFile = INVALID_HANDLE_VALUE;
	DWORD actualRead = 0;

	keyFile = CreateFileA(keyBlobFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (keyFile == INVALID_HANDLE_VALUE)
	{
		PrintError("CreateFileA for key file");
		goto cleanup;
	}

	if (!ReadFile(keyFile, rsaKey, *rsaKeyLength, &actualRead, NULL))
	{
		PrintError("ReadFile of readme");
		goto cleanup;
	}

	if (actualRead >= *rsaKeyLength)
	{
		fprintf(stderr, "key file is too long\n");
		goto cleanup;
	}

	*rsaKeyLength = actualRead;

	success = TRUE;
cleanup:
	if (keyFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(keyFile);
	}
	return success;
}

BOOL DecryptFileFromPath(const char* filePath, const char* extension, const char* keyBlobFile, BOOL force)
{
	BOOL success = FALSE;
	char decryptedPath[MAX_PATH] = { 0 };
	char readmePath[MAX_PATH] = { 0 };
	BYTE rsaKey[MAX_RSA_KEY_LENGTH] = { 0 };
	DWORD rsaKeyLength = sizeof(rsaKey);
	BYTE readmeKey[MAX_README_KEY_LENGTH] = { 0 };
	DWORD readmeKeyLength = sizeof(readmeKey);
	BYTE readmeTail[MAX_README_TAIL_LENGTH] = { 0 };
	DWORD readmeTailLength = sizeof(readmeTail);
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	BOOL createdFile = FALSE;

	if (strlen(filePath) > MAX_PATH)
	{
		fprintf(stderr, "file path %s is too long\n", filePath);
		goto cleanup;
	}

	if (!GetDecryptedFilePath(filePath, extension, decryptedPath))
	{
		fprintf(stderr, "failed to generate decrypted file path from %s\n", filePath);
		goto cleanup;
	}

	if (!GetReadmeFilePath(filePath, readmePath))
	{
		fprintf(stderr, "failed to get readme file path for %s\n", readmePath);
		goto cleanup;
	}

	if (!GetRsaKeyFromFile(keyBlobFile, rsaKey, &rsaKeyLength))
	{
		fprintf(stderr, "failed to read rsa key from %s\n", rsaKey);
		goto cleanup;
	}

	if (!GetKeyAndTailFromReadme(readmePath, readmeKey, &readmeKeyLength, readmeTail, &readmeTailLength))
	{
		fprintf(stderr, "failed to parse key and tail from readme at %s\n", readmePath);
		goto cleanup;
	}

	if (!CreateDecryptionKey(rsaKey, rsaKeyLength, readmeKey, readmeKeyLength, &hProv, &hKey))
	{
		fprintf(stderr, "failed to create decryption key from readme at %s\n", readmePath);
		goto cleanup;
	}

	if (!DecryptFileWithKeyAndTail(filePath, hKey, readmeTail, readmeTailLength, force, decryptedPath, &createdFile))
	{
		fprintf(stderr, "failed to decrypt file using key and tail\n");
		goto cleanup;
	}

	success = TRUE;
cleanup:
	if (!success && createdFile)
	{
		if (!DeleteFileA(decryptedPath))
		{
			PrintError("DeleteFile of decrypted file");
			fprintf(stderr, "WARNING: failed to remove unsuccessfully decrypted file at %s\n", decryptedPath);
		}
	}
	if (hKey != NULL)
	{
		CryptDestroyKey(hKey);
	}
	if (hProv != NULL)
	{
		CryptReleaseContext(hProv, 0);
	}
	return success;
}

void PrintUsage(const char* argv0)
{
	fprintf(stderr, "usage: %s -e <.extext> -k <keyfile> [-f] <encryptedfile>\n", argv0);
	fprintf(stderr, "\t-e\tencrypted file extension (starting with '.' character)\n");
	fprintf(stderr, "\t-k\tpath to private key to use for decryption\n");
	fprintf(stderr, "\t-f\tforce overwrite of existing decrypted file\n");
	fprintf(stderr, "\t-h\tshow this help\n");
}

int main(int argc, char* argv[])
{
	int opt = 0;
	BOOL force = FALSE;
	const char* keyBlobFile = NULL;
	const char* extension = NULL;
	const char* encryptedFile = NULL;

	while ((opt = getopt(argc, argv, "e:k:f")) != -1)
	{
		switch (opt)
		{
		case 'e':
			if (extension)
			{
				fprintf(stderr, "you may only specify a extension\n");
				return 1;
			}
			extension = optarg;
			if (extension[0] != '.')
			{
				fprintf(stderr, "extension must start with a '.' character\n");
				return 1;
			}
			break;

		case 'k':
			if (keyBlobFile)
			{
				fprintf(stderr, "you may only specify a single key file\n");
				return 1;
			}
			keyBlobFile = optarg;
			break;

		case 'f':
			force = TRUE;
			break;

		case 'h':
			PrintUsage(argv[0]);
			return 0;

		default:
			PrintUsage(argv[0]);
			return 1;
		}
	}

	if (optind >= argc) {
		PrintUsage(argv[0]);
		return 1;
	}
	encryptedFile = argv[optind];
	if (!encryptedFile || !extension || !keyBlobFile)
	{
		PrintUsage(argv[0]);
		return 1;
	}
	
	if (!DecryptFileFromPath(encryptedFile, extension, keyBlobFile, force))
	{
		fprintf(stderr, "failed to decrypt file\n");
		return 1;
	}
	fprintf(stderr, "file successfully decrypted\n");
	return 0;
}
