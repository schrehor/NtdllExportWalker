#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>

#define MAX_LOADER_ENTRIES 1024
#define MAX_EXPORT_TEXT 4096

typedef struct
{
	const BYTE* base;
	SIZE_T size;
	WORD format;
	IMAGE_DATA_DIRECTORY directory;
	IMAGE_EXPORT_DIRECTORY exports;
} EXPORT_VIEW;

typedef struct
{
	char name[MAX_EXPORT_TEXT];
	char forwarder[MAX_EXPORT_TEXT];
	DWORD ordinal;
	DWORD rva;
	BOOL forwarded;
} EXPORT_ENTRY;

static const void* AddAddress(const void* base, SIZE_T offset)
{
	if (!base || (ULONG_PTR)base > ~(ULONG_PTR)0 - offset)
		return NULL;
	return (const void*)((ULONG_PTR)base + offset);
}

static BOOL ReadLocal(const void* address, void* output, SIZE_T size)
{
	SIZE_T copied = 0;
	if (address == NULL || (ULONG_PTR)address > ~(ULONG_PTR)0 - size)
		return FALSE;

	return ReadProcessMemory(GetCurrentProcess(), address, output, size, &copied)
		&& copied == size;
}

static BOOL MatchModuleName(
	const UNICODE_STRING* name,
	const wchar_t* expected,
	BOOL* match)
{
	wchar_t tail[64] = { 0 };
	SIZE_T expectedLength = wcslen(expected);
	SIZE_T length = name->Length / sizeof(wchar_t);
	SIZE_T count;
	SIZE_T offset;
	ULONG_PTR address = (ULONG_PTR)name->Buffer;

	*match = FALSE;
	if (expectedLength == 0 || expectedLength + 1 >= _countof(tail)
		|| name->Length % sizeof(wchar_t) != 0
		|| name->Length > name->MaximumLength)
		return FALSE;
	if (length < expectedLength)
		return TRUE;

	count = length > expectedLength ? expectedLength + 1 : expectedLength;
	offset = name->Length - count * sizeof(wchar_t);
	if (address == 0 || address > ~(ULONG_PTR)0 - offset
		|| !ReadLocal((const void*)(address + offset), tail,
			count * sizeof(wchar_t)))
		return FALSE;

	if (count > expectedLength && tail[0] != L'\\' && tail[0] != L'/')
		return TRUE;
	*match = _wcsnicmp(tail + count - expectedLength, expected, expectedLength) == 0;
	return TRUE;
}

static BOOL WalkLoaderList(
	const LIST_ENTRY* headAddress,
	const wchar_t* expected,
	HMODULE* module,
	DWORD* visitedCount,
	const wchar_t** error)
{
	LIST_ENTRY head;
	const LIST_ENTRY* visited[MAX_LOADER_ENTRIES];
	const LIST_ENTRY* previous = headAddress;
	const LIST_ENTRY* current;
	HMODULE found = NULL;

	*module = NULL;
	*visitedCount = 0;
	if (!ReadLocal(headAddress, &head, sizeof(head)) || !head.Flink || !head.Blink)
	{
		*error = L"Loader-list head is unavailable";
		return FALSE;
	}

	current = head.Flink;
	while (current != headAddress)
	{
		LDR_DATA_TABLE_ENTRY entry;
		BOOL matches;
		ULONG_PTR address = (ULONG_PTR)current;
		SIZE_T linkOffset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (*visitedCount == MAX_LOADER_ENTRIES)
		{
			*error = L"Loader-list traversal exceeded its entry limit";
			return FALSE;
		}
		for (DWORD i = 0; i < *visitedCount; ++i)
		{
			if (visited[i] == current)
			{
				*error = L"Loader list contains a cycle outside its head";
				return FALSE;
			}
		}
		visited[(*visitedCount)++] = current;
		if (address < linkOffset
			|| !ReadLocal((const void*)(address - linkOffset), &entry, sizeof(entry))
			|| entry.InMemoryOrderLinks.Blink != previous
			|| !entry.InMemoryOrderLinks.Flink)
		{
			*error = L"Loader entry is unreadable or its links changed";
			return FALSE;
		}
		if (!MatchModuleName(&entry.FullDllName, expected, &matches))
		{
			*error = L"Loader module name is malformed or unreadable";
			return FALSE;
		}
		if (matches)
		{
			if (found || !entry.DllBase)
			{
				*error = L"Loader module name is ambiguous or its base is null";
				return FALSE;
			}
			found = (HMODULE)entry.DllBase;
		}
		previous = current;
		current = entry.InMemoryOrderLinks.Flink;
	}
	if (head.Blink != previous || !found)
	{
		*error = found ? L"Loader-list tail changed" : L"Requested loader module was not found";
		return FALSE;
	}
	*module = found;
	return TRUE;
}

static BOOL FindNtdll(HMODULE* module, DWORD* count, const wchar_t** error)
{
	PPEB peb = NULL;
	PPEB_LDR_DATA loader = NULL;
	const BYTE* teb = (const BYTE*)NtCurrentTeb();

	if (!ReadLocal(AddAddress(teb, offsetof(TEB, ProcessEnvironmentBlock)), &peb, sizeof(peb))
		|| !peb || !ReadLocal(AddAddress(peb, offsetof(PEB, Ldr)), &loader, sizeof(loader))
		|| !loader)
	{
		*error = L"Current TEB/PEB loader pointer is unavailable";
		return FALSE;
	}
	return WalkLoaderList((const LIST_ENTRY*)AddAddress(loader,
		offsetof(PEB_LDR_DATA, InMemoryOrderModuleList)), L"ntdll.dll", module, count, error);
}

static BOOL Fits(SIZE_T size, SIZE_T offset, SIZE_T length)
{
	return offset <= size && length <= size - offset;
}

static BOOL ReadImage(const EXPORT_VIEW* image, SIZE_T offset, void* output, SIZE_T size)
{
	return Fits(image->size, offset, size)
		&& ReadLocal(AddAddress(image->base, offset), output, size);
}

static BOOL ReadImageString(
	const EXPORT_VIEW* image,
	DWORD rva,
	SIZE_T limit,
	char output[MAX_EXPORT_TEXT])
{
	if (limit > image->size || rva >= limit)
		return FALSE;
	for (SIZE_T i = 0; i < MAX_EXPORT_TEXT; ++i)
	{
		if (!Fits(limit, (SIZE_T)rva + i, 1)
			|| !ReadImage(image, (SIZE_T)rva + i, &output[i], 1))
			return FALSE;
		if (output[i] == '\0')
			return i != 0;
	}
	return FALSE;
}

static BOOL GetImageSpan(HMODULE module, SIZE_T* span)
{
	ULONG_PTR start = (ULONG_PTR)module;
	ULONG_PTR cursor = start;

	for (unsigned i = 0; i < 1024; ++i)
	{
		MEMORY_BASIC_INFORMATION memory;
		if (!VirtualQuery((const void*)cursor, &memory, sizeof(memory)))
			return FALSE;
		if (memory.AllocationBase != module)
		{
			*span = cursor - start;
			return *span != 0;
		}
		if (memory.Type != MEM_IMAGE || memory.RegionSize == 0
			|| (ULONG_PTR)memory.BaseAddress > ~(ULONG_PTR)0 - memory.RegionSize)
			return FALSE;
		ULONG_PTR next = (ULONG_PTR)memory.BaseAddress + memory.RegionSize;
		if (next <= cursor || next - start > MAXDWORD)
			return FALSE;
		cursor = next;
	}
	return FALSE;
}

static BOOL OpenExports(
	const BYTE* base,
	SIZE_T span,
	EXPORT_VIEW* image,
	const wchar_t** error)
{
	IMAGE_DOS_HEADER dos;
	IMAGE_FILE_HEADER file;
	DWORD signature;
	DWORD imageSize, headerSize, directories;
	SIZE_T optionalOffset, fixedSize;
	SIZE_T imageSizeOffset, headerSizeOffset, countOffset;

	ZeroMemory(image, sizeof(*image));
	image->base = base;
	image->size = span;
	*error = L"PE headers are invalid, truncated or unreadable";
	if (!ReadImage(image, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE
		|| dos.e_lfanew < (LONG)sizeof(dos)
		|| !ReadImage(image, (SIZE_T)dos.e_lfanew, &signature, sizeof(signature))
		|| signature != IMAGE_NT_SIGNATURE
		|| !ReadImage(image, (SIZE_T)dos.e_lfanew + sizeof(signature), &file, sizeof(file))
		|| !(file.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
		return FALSE;

	optionalOffset = (SIZE_T)dos.e_lfanew + sizeof(signature) + sizeof(file);
	if (!Fits(span, optionalOffset, file.SizeOfOptionalHeader)
		|| file.SizeOfOptionalHeader < sizeof(WORD)
		|| !ReadImage(image, optionalOffset, &image->format, sizeof(image->format)))
		return FALSE;
	if (image->format == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		fixedSize = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
		imageSizeOffset = offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage);
		headerSizeOffset = offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders);
		countOffset = offsetof(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes);
	}
	else if (image->format == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		fixedSize = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
		imageSizeOffset = offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage);
		headerSizeOffset = offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders);
		countOffset = offsetof(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes);
	}
	else
		return FALSE;

	if (file.SizeOfOptionalHeader < fixedSize
		|| !ReadImage(image, optionalOffset + imageSizeOffset, &imageSize, sizeof(imageSize))
		|| !ReadImage(image, optionalOffset + headerSizeOffset, &headerSize, sizeof(headerSize))
		|| !ReadImage(image, optionalOffset + countOffset, &directories, sizeof(directories))
		|| !imageSize || imageSize > span || headerSize > imageSize
		|| optionalOffset + file.SizeOfOptionalHeader > headerSize
		|| !directories
		|| directories > (file.SizeOfOptionalHeader - fixedSize) / sizeof(IMAGE_DATA_DIRECTORY)
		|| !ReadImage(image, optionalOffset + fixedSize, &image->directory, sizeof(image->directory)))
		return FALSE;

	image->size = imageSize;
	*error = L"PE export directory or tables are outside the image";
	if (!image->directory.VirtualAddress || image->directory.Size < sizeof(image->exports)
		|| !Fits(imageSize, image->directory.VirtualAddress, image->directory.Size)
		|| !ReadImage(image, image->directory.VirtualAddress, &image->exports, sizeof(image->exports)))
		return FALSE;

	const IMAGE_EXPORT_DIRECTORY* exports = &image->exports;
	if (!exports->NumberOfFunctions || !exports->AddressOfFunctions
		|| exports->NumberOfFunctions > imageSize / sizeof(DWORD)
		|| !Fits(imageSize, exports->AddressOfFunctions,
			(SIZE_T)exports->NumberOfFunctions * sizeof(DWORD)))
		return FALSE;
	if (exports->NumberOfNames
		&& (!exports->AddressOfNames || !exports->AddressOfNameOrdinals
			|| exports->NumberOfNames > imageSize / sizeof(DWORD)
			|| !Fits(imageSize, exports->AddressOfNames,
				(SIZE_T)exports->NumberOfNames * sizeof(DWORD))
			|| !Fits(imageSize, exports->AddressOfNameOrdinals,
				(SIZE_T)exports->NumberOfNames * sizeof(WORD))))
		return FALSE;
	return TRUE;
}

static BOOL ReadExport(
	const EXPORT_VIEW* image,
	DWORD index,
	EXPORT_ENTRY* entry,
	const wchar_t** error)
{
	DWORD nameRva;
	WORD ordinal;
	const IMAGE_EXPORT_DIRECTORY* exports = &image->exports;
	SIZE_T directoryEnd = (SIZE_T)image->directory.VirtualAddress + image->directory.Size;

	*error = L"Named export has an invalid name, ordinal, address or forwarder";
	ZeroMemory(entry, sizeof(*entry));
	if (index >= exports->NumberOfNames
		|| !ReadImage(image, (SIZE_T)exports->AddressOfNames + index * sizeof(DWORD),
			&nameRva, sizeof(nameRva))
		|| !ReadImageString(image, nameRva, image->size, entry->name)
		|| !ReadImage(image, (SIZE_T)exports->AddressOfNameOrdinals + index * sizeof(WORD),
			&ordinal, sizeof(ordinal))
		|| ordinal >= exports->NumberOfFunctions || exports->Base > MAXDWORD - ordinal
		|| !ReadImage(image, (SIZE_T)exports->AddressOfFunctions + ordinal * sizeof(DWORD),
			&entry->rva, sizeof(entry->rva))
		|| !entry->rva || entry->rva >= image->size)
		return FALSE;

	entry->ordinal = exports->Base + ordinal;
	entry->forwarded = entry->rva >= image->directory.VirtualAddress && entry->rva < directoryEnd;
	return !entry->forwarded
		|| ReadImageString(image, entry->rva, directoryEnd, entry->forwarder);
}

static BOOL PrintExports(
	HMODULE module,
	const EXPORT_VIEW* image,
	BOOL all,
	const char* wanted,
	BOOL compare,
	const wchar_t** error)
{
	DWORD displayed = 0;
	printf("[+] PE format - %s\n", image->format == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE32+" : "PE32");
	printf("[+] Named exports - %lu\n", image->exports.NumberOfNames);
	for (DWORD i = 0; i < image->exports.NumberOfNames; ++i)
	{
		EXPORT_ENTRY entry;
		if (!ReadExport(image, i, &entry, error))
			return FALSE;
		if (wanted ? _stricmp(entry.name, wanted) != 0
			: (!all && strncmp(entry.name, "Nt", 2) != 0 && strncmp(entry.name, "Zw", 2) != 0))
			continue;

		const void* address = AddAddress(image->base, entry.rva);
		const char* result = "NOT_REQUESTED";
		if (compare)
		{
			FARPROC resolved = GetProcAddress(module, entry.name);
			result = entry.forwarded ? (resolved ? "RESOLVED" : "UNRESOLVED")
				: ((const void*)resolved == address ? "MATCH" : "MISMATCH");
			if (!resolved || (!entry.forwarded && (const void*)resolved != address))
			{
				*error = L"Export address comparison failed";
				return FALSE;
			}
		}
		printf("[+] EXPORT %s ordinal=%lu rva=0x%08lX %s=%s comparison=%s\n",
			entry.name, entry.ordinal, entry.rva, entry.forwarded ? "forwarder" : "kind",
			entry.forwarded ? entry.forwarder : "DIRECT", result);
		printf("[+] ADDRESS %s %p\n", entry.name, address);
		++displayed;
		if (wanted)
			break;
	}
	printf("[+] Displayed exports - %lu\n", displayed);
	if (wanted && !displayed)
	{
		*error = L"Requested export name was not found";
		return FALSE;
	}
	return TRUE;
}

static void Usage(void)
{
	printf("Usage: NtdllExportWalker.exe [--base | --all | --name NAME] [--compare]\n");
	printf("       NtdllExportWalker.exe --help\n");
}

int wmain(int argc, wchar_t* argv[])
{
	BOOL compare = FALSE;
	BOOL base = FALSE;
	BOOL all = FALSE;
	BOOL selected = FALSE;
	char wanted[MAX_EXPORT_TEXT] = { 0 };
	HMODULE module = NULL;
	DWORD count = 0;
	const wchar_t* error = NULL;

	for (int i = 1; i < argc; ++i)
	{
		if (wcscmp(argv[i], L"--help") == 0 && argc == 2)
		{
			Usage();
			return EXIT_SUCCESS;
		}
		if (wcscmp(argv[i], L"--compare") == 0 && !compare)
			compare = TRUE;
		else if (wcscmp(argv[i], L"--base") == 0 && !selected)
			base = selected = TRUE;
		else if (wcscmp(argv[i], L"--all") == 0 && !selected)
			all = selected = TRUE;
		else if (wcscmp(argv[i], L"--name") == 0 && !selected && i + 1 < argc)
		{
			SIZE_T length = wcslen(argv[++i]);
			if (!length || length >= sizeof(wanted))
			{
				fprintf(stderr, "[-] Export name is empty or too long\n");
				return EXIT_FAILURE;
			}
			for (SIZE_T j = 0; j < length; ++j)
			{
				if (argv[i][j] > 127 || argv[i][j] < 1)
				{
					fprintf(stderr, "[-] Export names must use ASCII bytes\n");
					return EXIT_FAILURE;
				}
				wanted[j] = (char)argv[i][j];
			}
			selected = TRUE;
		}
		else
		{
			Usage();
			return EXIT_FAILURE;
		}
	}
	if (!FindNtdll(&module, &count, &error))
	{
		fwprintf(stderr, L"[-] %ls\n", error);
		return EXIT_FAILURE;
	}
	printf("[+] Discovery - current-process PEB loader list\n");
	printf("[+] Loader entries - %lu\n", count);
	printf("[+] NTDLL base - %p\n", (void*)module);
	if (compare)
	{
		HMODULE apiModule = GetModuleHandleW(L"ntdll.dll");
		printf("[+] Module API comparison - %s\n", apiModule == module ? "MATCH" : "MISMATCH");
		if (apiModule != module)
			return EXIT_FAILURE;
	}
	if (!base)
	{
		EXPORT_VIEW image;
		SIZE_T span;
		if (!GetImageSpan(module, &span))
		{
			fprintf(stderr, "[-] NTDLL image mapping is unavailable\n");
			return EXIT_FAILURE;
		}
		if (!OpenExports((const BYTE*)module, span, &image, &error)
			|| !PrintExports(module, &image, all, wanted[0] ? wanted : NULL, compare, &error))
		{
			fwprintf(stderr, L"[-] %ls\n", error);
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}
