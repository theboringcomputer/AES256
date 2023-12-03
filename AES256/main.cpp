#include <iostream>
#include <string>
#include <Windows.h>
#include <wincrypt.h>
#include <Fileapi.h>
#include <stdlib.h>

#define ENCRYPTION_ALGORITHM CALG_AES_256
#define BLOCK_SIZE 64

using namespace std;

void usage()
{
	cout<<"USAGE:AES256 [ENCRYPT | DECRYPT] [SOURCE FILE] [DESTINATION FILE NAME] [PASSWORD]";
}

int main(int argc, char* argv[])
{
	char option_encrypt[] = "ENCRYPT";
	HCRYPTPROV provider;
	HCRYPTHASH hash;
	LPTSTR password;
	HCRYPTKEY encryption_key;
	HANDLE open_source_file;
	LPCSTR source_file;
	DWORD bytes;
	DWORD buffer_length;
	PBYTE buffer;
	LPCSTR destination_file_name;
	HANDLE create_destination_file;
	int check;
	bool end_of_file = 0;
	DWORD count;
	char option_decrypt[] = "DECRYPT";
	int decryption_failed;

	if(argc == 5)
	{
		if(strcmp("AES256", argv[0]) == 0)
		{
			if(strcmp(option_encrypt, argv[1]) == 0)
			{
				CryptAcquireContext(&provider, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
				CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash);
				password = argv[4];
				CryptHashData(hash, (BYTE*)password, lstrlen(password), 0);
				CryptDeriveKey(provider, ENCRYPTION_ALGORITHM, hash, 0, &encryption_key);
				source_file = argv[2];
				open_source_file = CreateFile(source_file, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
				bytes = 1000 - 1000 % BLOCK_SIZE;
				if(BLOCK_SIZE > 1)
				{
					buffer_length = bytes + BLOCK_SIZE;
				}
				else
				{
					buffer_length = bytes;
				}
				buffer = (BYTE*)malloc(buffer_length);
				destination_file_name = argv[3];
				create_destination_file = CreateFile(destination_file_name, FILE_WRITE_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
				check = int(create_destination_file);
				if(check < 0)
				{
					usage();
				}
				else
				{
					do
					{
						ReadFile(open_source_file, buffer, bytes, &count, 0);
						if(count < bytes)
						{
							end_of_file = 1;
						}
						CryptEncrypt(encryption_key, 0, end_of_file, 0, buffer, &count, buffer_length);
						WriteFile(create_destination_file, buffer, count, &count, 0);
					} 
					while(end_of_file == 0);
					cout<<"Encrypted";
					CloseHandle(open_source_file);
					free(buffer);
					CryptReleaseContext(provider, 0);
					CryptDestroyHash(hash);
					CryptDestroyKey(encryption_key);
					CloseHandle(create_destination_file);
				}
			}
			else
			{

				if(strcmp(option_decrypt, argv[1]) == 0)
				{
					CryptAcquireContext(&provider, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
					CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash);
					password = argv[4];
					CryptHashData(hash, (BYTE*)password, lstrlen(password), 0);
					CryptDeriveKey(provider, ENCRYPTION_ALGORITHM, hash, 0, &encryption_key);
					source_file = argv[2];
					open_source_file = CreateFile(source_file, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
					bytes = 1000 - 1000 % BLOCK_SIZE;
					buffer_length = bytes;
					buffer = (PBYTE)malloc(buffer_length);
					destination_file_name = argv[3];
					create_destination_file = CreateFile(destination_file_name, FILE_WRITE_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
					do
					{
						ReadFile(open_source_file, buffer, bytes, &count, 0);
						if(count < bytes)
						{
							end_of_file = 1;
						}
						if(CryptDecrypt(encryption_key, 0, end_of_file, 0, buffer, &count) == 1)
						{
							WriteFile(create_destination_file, buffer, count, &count, 0);
						}
						else
						{
							decryption_failed = 1;
							break;
						}
					} 
					while(end_of_file == 0);
					if(decryption_failed == 1)
					{
						CloseHandle(open_source_file);
						free(buffer);
						CryptReleaseContext(provider, 0);
						CryptDestroyHash(hash);
						CryptDestroyKey(encryption_key);
						CloseHandle(create_destination_file);
						remove(argv[3]);
						cout<<"Decryption failed";
					}
					else
					{
						CloseHandle(open_source_file);
						free(buffer);
						CryptReleaseContext(provider, 0);
						CryptDestroyHash(hash);
						CryptDestroyKey(encryption_key);
						CloseHandle(create_destination_file);
						cout<<"Decrypted";
					}
				}
				else
				{
					usage();
				}
			}
		}
		else
		{
			usage();
		}
	}
	else
	{
		usage();
	}
	return 0;
}