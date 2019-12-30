#include "pefile.h"
#include <iostream>
#include <windows.h>


int main()
{
	wchar_t* wszTargetModule;
 
	DWORD dwSize,
		  dwExtraSpace,
		  dwLoadLibrary;
	
	DWORD dwTemp;
 
	PEFile* pFile;
 
	BYTE* pCurrent,
		* pFilePointer,
		* pEntryAddress,
		* pFileContents;
	
	ofstream out;
 
	IMAGE_SECTION_HEADER* pSection;
 
	DWORD dwTotalSize,
		  dwRelocSize;
	
	IMAGE_BASE_RELOCATION* pReloc;
 
	RelocationEntry* pRelocEntry;
 
	RelocationEntry relocEntry[2];
 
 
	wszTargetModule = L"C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\bin\\xor hook.dll";
 
	// Get the file content
	pFileContents = GetFileContents("C:\\c1xx.dll", dwSize);
 
	// Initalize
	pFile = new PEFile(pFileContents, dwSize);
 
	// Erases the cached import table rather than fix it
	pFile->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	pFile->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
 
	// Create a new section called temp
	// MAX_PATH * 2 for wchar + 0x200 for code
	pSection = pFile->CreateSection(".temp", 0x400);
	
 
	// Get the IAT address of LoadLibraryW
	dwLoadLibrary = pFile->GetImportAddress("Kernel32.dll", "LoadLibraryW");
 
	if(dwLoadLibrary != NULL)
	{
		// Get the file pointer of my new section
		pFilePointer = (BYTE*)pFile->RVAToFilePointer(pSection->VirtualAddress);
		pCurrent = pFilePointer;
 
		// Write the target module name
		memcpy(pCurrent, wszTargetModule, (wcslen(wszTargetModule) + 1) * 2);
		pCurrent += MAX_PATH * 2;
 
		pEntryAddress = pCurrent;
 
		// push module file name
		*pCurrent++ = 0x68;
		pFilePointer = (BYTE*)pFile->FilePointerToImagePointer(pFilePointer);
		*(DWORD*)pCurrent = (DWORD)pFilePointer;
		pCurrent += 4;
 
		// call dword ptr [LoadLibrary]
		*pCurrent++ = 0xFF;
		*pCurrent++ = 0x15;
		*(DWORD*)pCurrent = dwLoadLibrary;
		pCurrent += 4;
		
		// Jump to original entry point
		dwTemp = (DWORD)pFile->FilePointerToImagePointer((void*)pCurrent);
 
		*pCurrent++ = 0xE9;
		*(DWORD*)pCurrent = ((DWORD)pFile->RVAToImagePointer(pFile->ntHeader->OptionalHeader.AddressOfEntryPoint) - dwTemp - 5);
		pCurrent += 4;
 
		// Set the entrace address to the new section
		pFile->ntHeader->OptionalHeader.AddressOfEntryPoint = pFile->FileAddressToRVA(pFile->FilePointerToAddress((void*)pEntryAddress));
 
 
 
		// Create a new relocation header
		pReloc = new IMAGE_BASE_RELOCATION();
		pReloc->VirtualAddress = pSection->VirtualAddress;
		pReloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + (sizeof(RelocationEntry) * 2);
 
		// Initailize the two relocations
		relocEntry[0].SetType(3);
		relocEntry[0].SetOffset(MAX_PATH * 2 + 1); // push instruction
 
		relocEntry[1].SetType(3);
		relocEntry[1].SetOffset(MAX_PATH * 2 + 7); // call dword ptr [LoadLibrary]
 
		// Get the .reloc section
		pSection = pFile->GetSectionFromRVA(pFile->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
 
		dwExtraSpace = pSection->SizeOfRawData - pSection->Misc.VirtualSize;
 
		if(dwExtraSpace >= (sizeof(IMAGE_BASE_RELOCATION) + sizeof(RelocationEntry) * 2))
		{
			// Get the end of the reloc section
			pCurrent = (BYTE*)pFile->FileAddressToPointer(pSection->PointerToRawData + pFile->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	
			// Add the new header
			memcpy(pCurrent, pReloc, sizeof(IMAGE_BASE_RELOCATION));
			pCurrent += sizeof(IMAGE_BASE_RELOCATION);
 
			// Add the new entries
			memcpy(pCurrent, relocEntry, sizeof(relocEntry));
 
			// Set the new size of the relocations section
			pFile->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += pReloc->SizeOfBlock;
		
			// Write it to file
			out.open("C:\\c1xx - patched.dll", ios::out | ios::binary);
 
			if(out.is_open() == true)
			{
				out.write((char*)&pFile->content[0], pFile->content.size());
				out.close();
			}
		}
		else
			printf("Not enough room to add relocation\n");
	}
	else
		printf("This file does not have LoadLibraryW\n");
 
 
	cin.get();
 
	return 0;
}
 
 
 
unsigned int RoundAlignment(int iValue, unsigned int iRound)
{
  return iRound * ((iRound + iValue - 1) / iRound);
}
 
BYTE* GetFileContents(string filename, DWORD& dwSize)
{
	ifstream in;
 
	BYTE* pContents;
 
 
	dwSize = 0;
	pContents = NULL;
 
	in.open(filename, ios::in | ios::binary);
 
	if(in.is_open() == true)
	{
		in.seekg(0, ios::end);
		dwSize = in.tellg();
		in.seekg(0, ios::beg);
		
		pContents = new BYTE[dwSize];
		in.read((char*)pContents, dwSize);
		in.close();
	}
 
	return pContents;
}