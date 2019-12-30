class PEFile
{
public:
	IMAGE_DOS_HEADER* dosHeader;
 
	IMAGE_NT_HEADERS* ntHeader;
 
	IMAGE_SECTION_HEADER* sections;
 
 
	PEFile(BYTE* pContent, DWORD dwSize);
 
	IMAGE_SECTION_HEADER* CreateSection(DWORD dwSize);
 
	IMAGE_SECTION_HEADER* GetFirstSection();
 
	IMAGE_SECTION_HEADER* GetSectionFromRVA(DWORD dwAddress);
 
	IMAGE_SECTION_HEADER* PEFile::GetSectionFromFileAddress(DWORD dwAddress);
 
 
	DWORD RVAToFileAddress(DWORD dwAddress);
 
	DWORD RVAToFileAddress(IMAGE_SECTION_HEADER* pSection, DWORD dwAddress);
 
	void* RVAToPointer(DWORD dwAddress);
 
	void* RVAToFilePointer(DWORD dwAddress);
 
	void* FileAddressToPointer(DWORD dwAddress);
 
	DWORD PointerToRVA(DWORD dwAddress);
 
	void* AdjustPointerByNewDelta(void* pAddress);
 
	DWORD GetImportAddress(char* szModuleName, char* szFunctionName);
 
	IMAGE_SECTION_HEADER* CreateSection(char* szName, DWORD dwSize);
 
	DWORD FilePointerToAddress(void* pAddress);
 
	DWORD FileAddressToRVA(DWORD dwAddress);
 
	void* RVAToImagePointer(DWORD dwAddress);
	
	void* FilePointerToImagePointer(void* pAddress);
 
	bool LoadHeaders();
 
	vector<BYTE> content;
 
private:
 
	DWORD dwNewContentDelta;
};
 
PEFile::PEFile(BYTE* pContent, DWORD dwSize)
{
	dwNewContentDelta = 0;
	content.insert(content.end(), pContent, pContent + dwSize);
 
	if(LoadHeaders() == false)
		printf("Not a valid file\n");
}
 
IMAGE_SECTION_HEADER* PEFile::GetFirstSection()
{
	return (IMAGE_SECTION_HEADER*)((DWORD)this->ntHeader + sizeof(IMAGE_NT_HEADERS));
}
 
bool PEFile::LoadHeaders()
{
	bool bValid;
 
 
	bValid = false;
 
	dosHeader = (IMAGE_DOS_HEADER*)&content[0];
 
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		ntHeader = (IMAGE_NT_HEADERS*)((DWORD)&content[0] + dosHeader->e_lfanew);
		
		if(ntHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			sections = IMAGE_FIRST_SECTION(ntHeader);
			bValid = true;
		}
	}
 
	return bValid;
}
 
IMAGE_SECTION_HEADER* PEFile::CreateSection(char* szName, DWORD dwSize)
{
	BYTE* pCave;
 
	DWORD dwFarthest,
		  dwAddress;
 
	IMAGE_SECTION_HEADER* pSection,
						* pTemp;
 
	int iTargetIndex,
		iBiggestVirtual;
	
 
	// Save the current address for delta
	dwAddress = (DWORD)&content[0];
 
	// Create the section object
	pSection = new IMAGE_SECTION_HEADER();
	strcpy((char*)pSection->Name, szName);
	pSection->Characteristics = IMAGE_SCN_MEM_EXECUTE;
	pSection->NumberOfLinenumbers = 0;
	pSection->NumberOfRelocations = 0;
	pSection->PointerToRelocations = NULL;
	pSection->PointerToLinenumbers = NULL;
	pSection->SizeOfRawData = dwSize;
	pSection->Misc.VirtualSize = dwSize;
	
 
	pTemp = this->GetFirstSection();
 
	// Fix all the file pointers in the sections
	for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
		pTemp[i].PointerToRawData += 0x200;
 
 
	// Insert the new section
	pTemp = this->GetFirstSection();
	pCave = (BYTE*)malloc(0x200);
	
	ZeroMemory(pCave, 0x200);
	memcpy((void*)pCave, (void*)pSection, sizeof(IMAGE_SECTION_HEADER));
 
	// Insert the bytes
	content.insert(content.begin() + ((DWORD)&pTemp[ntHeader->FileHeader.NumberOfSections] - (DWORD)&this->content[0]), (BYTE*)pCave, (BYTE*)pCave + 0x200);
 
	// Reload the header
	LoadHeaders();
 
	ntHeader->OptionalHeader.SizeOfHeaders = RoundAlignment(dosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader + ((ntHeader->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER)), ntHeader->OptionalHeader.FileAlignment);
	ntHeader->OptionalHeader.SizeOfImage = RoundAlignment(ntHeader->OptionalHeader.SizeOfImage + dwSize, ntHeader->OptionalHeader.SectionAlignment);
	
	// Get the last section
	pTemp = this->GetFirstSection();
	pSection = (IMAGE_SECTION_HEADER*)&content[((DWORD)&pTemp[ntHeader->FileHeader.NumberOfSections] - (DWORD)&this->content[0])];
 
	// Increase the amount of sections
	ntHeader->FileHeader.NumberOfSections++;
		
	// Create the new section content
	pCave = (BYTE*)malloc(dwSize);
	ZeroMemory(pCave, dwSize);
 
	// Get the farthest section
	iTargetIndex = 0;
	iBiggestVirtual = 0;
 
	pTemp = this->GetFirstSection();
 
	for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		if(pTemp[i].VirtualAddress > iBiggestVirtual)
		{
			iBiggestVirtual = pTemp[i].VirtualAddress;
			iTargetIndex = i;
		}
	}
 
	// Select that section
	pTemp = &pTemp[iTargetIndex];
 
	// Set its address
	pSection->VirtualAddress = RoundAlignment(pTemp->VirtualAddress + pTemp->SizeOfRawData, this->ntHeader->OptionalHeader.SectionAlignment);
	pSection->PointerToRawData = pTemp->PointerToRawData + pTemp->SizeOfRawData;
 
	// Insert the new section content
	content.insert(content.begin() + pSection->PointerToRawData, pCave, pCave + dwSize);
 
	// Calculate the delta
	dwNewContentDelta = (DWORD)&content[0] - dwAddress;
 
	return pSection;
}
 
IMAGE_SECTION_HEADER* PEFile::GetSectionFromRVA(DWORD dwAddress)
{
	IMAGE_SECTION_HEADER* pSection;
 
 
	pSection = this->GetFirstSection();
 
	for(int i = 0; i < this->ntHeader->FileHeader.NumberOfSections; i++)
	{
		if(dwAddress >= pSection->VirtualAddress && dwAddress < pSection->VirtualAddress + pSection->SizeOfRawData)
			break;
 
		pSection++;
 
		if(i == this->ntHeader->FileHeader.NumberOfSections - 1)
			pSection = NULL;
 
	}
 
	return pSection;
}
 
void* PEFile::RVAToPointer(DWORD dwAddress)
{
	void* pResult;
 
	DWORD dwTemp;
 
 
	pResult = this->FileAddressToPointer(dwAddress);
 
	return pResult;
}
 
void* PEFile::RVAToFilePointer(DWORD dwAddress)
{
	void* pResult;
 
	DWORD dwTemp;
 
 
	pResult = NULL;
	dwTemp = this->RVAToFileAddress(dwAddress);
 
	if(dwTemp != NULL)
		pResult = this->FileAddressToPointer(dwTemp);
 
	return pResult;
}
 
DWORD PEFile::RVAToFileAddress(DWORD dwAddress)
{
	DWORD dwResult;
 
	IMAGE_SECTION_HEADER* pSection;
 
 
	dwResult = NULL;
	pSection = this->GetSectionFromRVA(dwAddress);
 
	if(pSection != NULL)
		dwResult = this->RVAToFileAddress(pSection, dwAddress);
 
	return dwResult;
}
 
DWORD PEFile::RVAToFileAddress(IMAGE_SECTION_HEADER* pSection, DWORD dwAddress)
{
	DWORD dwDelta;
 
	dwDelta = pSection->VirtualAddress - pSection->PointerToRawData;
 
	return dwAddress - dwDelta;
}
 
void* PEFile::FileAddressToPointer(DWORD dwAddress)
{
	void* pResult;
 
 
	pResult = (void*)(&this->content[0] + dwAddress);
 
	return pResult;
}
 
IMAGE_SECTION_HEADER* PEFile::GetSectionFromFileAddress(DWORD dwAddress)
{
	IMAGE_SECTION_HEADER* pSection;
 
 
	pSection = this->GetFirstSection();
 
	for(int i = 0; i < this->ntHeader->FileHeader.NumberOfSections; i++)
	{
		if(dwAddress >= pSection->PointerToRawData && dwAddress < pSection->PointerToRawData + pSection->SizeOfRawData)
			break;
 
		pSection++;
 
		if(i == this->ntHeader->FileHeader.NumberOfSections - 1)
			pSection = NULL;
	}
 
	return pSection;
}
 
DWORD PEFile::FileAddressToRVA(DWORD dwAddress)
{
	DWORD dwDelta,
		  dwResult;
	
	IMAGE_SECTION_HEADER* pSection;
 
 
	pSection = this->GetSectionFromFileAddress(dwAddress);
	dwDelta = pSection->VirtualAddress - pSection->PointerToRawData;
	
	dwResult = dwAddress + dwDelta;
 
	return dwResult;
}
 
DWORD PEFile::FilePointerToAddress(void* pAddress)
{
	DWORD dwResult;
 
 
	dwResult = ((DWORD)pAddress - (DWORD)&this->content[0]);
 
	return dwResult;
}
 
DWORD PEFile::PointerToRVA(DWORD dwAddress)
{
	DWORD dwResult;
 
 
	dwResult = (dwAddress - (DWORD)&this->content[0]);
 
	return dwResult;
}
 
void* PEFile::AdjustPointerByNewDelta(void* pAddress)
{
	return (void*)((DWORD)pAddress + this->dwNewContentDelta);
}
 
DWORD PEFile::GetImportAddress(char* szModuleName, char* szFunctionName)
{
	DWORD dwResult;
 
	char* szTempModuleName;
 
	PIMAGE_THUNK_DATA pThunk,
					  pOriginalThunk;
	
	IMAGE_IMPORT_BY_NAME* pImportEntry;
 
	IMAGE_IMPORT_DESCRIPTOR* pImportDesc;
 
 
	dwResult = NULL;
	pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)this->RVAToFilePointer(this->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
 
	if(pImportDesc != NULL)
	{
		do
		{
			szTempModuleName = (char*)this->RVAToFilePointer((DWORD)pImportDesc->Name);
 
 
			if(stricmp(szTempModuleName, szModuleName) == 0)
			{
				pThunk = (PIMAGE_THUNK_DATA)(this->RVAToFilePointer(pImportDesc->OriginalFirstThunk));
				pOriginalThunk = (PIMAGE_THUNK_DATA)(this->RVAToPointer(pImportDesc->FirstThunk));
			
 
				// Iterate through all the IMAGE_IMPORT_BY_NAME pointers
 
				while(pThunk->u1.AddressOfData != NULL)
				{
					if(pThunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)
					{
						// fix me
						printf("Ordinal is %x\n", pThunk->u1.AddressOfData);
					}
					else
					{
						pImportEntry = (IMAGE_IMPORT_BY_NAME*)this->RVAToFilePointer(pThunk->u1.AddressOfData);
 
						if(stricmp((char*)pImportEntry->Name, szFunctionName) == 0)
						{
							dwResult = this->PointerToRVA((DWORD)pOriginalThunk) + this->ntHeader->OptionalHeader.ImageBase;
							break;
						}
					}
				
					pThunk++;
					pOriginalThunk++;
				}
			}
 
			pImportDesc++;
 
		}while((pImportDesc->Characteristics == NULL && 
				pImportDesc->Name == NULL && 
				pImportDesc->FirstThunk == NULL && 
				pImportDesc->ForwarderChain == NULL && 
				pImportDesc->OriginalFirstThunk == NULL && 
				pImportDesc->TimeDateStamp == NULL) == false && dwResult == NULL);
	}
 
	return dwResult;
}
 
void* PEFile::RVAToImagePointer(DWORD dwAddress)
{
	return (void*)(dwAddress + this->ntHeader->OptionalHeader.ImageBase);
}
 
void* PEFile::FilePointerToImagePointer(void* pAddress)
{
	void* pResult;
 
 
	pResult = (void*)this->FilePointerToAddress(pAddress);
	pResult = (void*)this->FileAddressToRVA((DWORD)pResult);
	pResult = this->RVAToImagePointer((DWORD)pResult);
 
	return pResult;
}
 
 
 
class RelocationEntry
{
public:
	WORD TypeAndOffset;
		
	void SetType(DWORD dwType)
	{
		// Erase the high nibble
		this->TypeAndOffset &= 0x0FFF;
 
		// Set the high nibble
		this->TypeAndOffset |= (dwType << 12);
	}
 
	void SetOffset(DWORD dwOffset)
	{
		// Erase the lower 12 bits
		this->TypeAndOffset &= 0xF000;
 
		// Set the lower 12 bits
		this->TypeAndOffset |= (dwOffset << 0);
	}
 
	DWORD GetType()
	{
		DWORD dwResult;
 
			
		dwResult = ((this->TypeAndOffset >> 12) & 0x0F);
 
		return dwResult;
	}
 
	DWORD GetOffset()
	{
		DWORD dwResult;
 
			
		dwResult = (this->TypeAndOffset & 0x0FFF);
 
		return dwResult;
	}
};