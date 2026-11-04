#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stddef.h>
#include <wchar.h>
#include <stdlib.h>

#define MAX_LOADER_ENTRIES 1024

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

	if (!ReadLocal(teb + offsetof(TEB, ProcessEnvironmentBlock), &peb, sizeof(peb))
		|| !peb || !ReadLocal((const BYTE*)peb + offsetof(PEB, Ldr), &loader, sizeof(loader))
		|| !loader)
	{
		*error = L"Current TEB/PEB loader pointer is unavailable";
		return FALSE;
	}
	return WalkLoaderList(&loader->InMemoryOrderModuleList, L"ntdll.dll", module, count, error);
}

static void Usage(void)
{
	printf("Usage: NtdllExportWalker.exe [--base] [--compare]\n");
	printf("       NtdllExportWalker.exe --help\n");
}

int wmain(int argc, wchar_t* argv[])
{
	BOOL compare = FALSE;
	BOOL base = FALSE;
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
		else if (wcscmp(argv[i], L"--base") == 0 && !base)
			base = TRUE;
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
	return EXIT_SUCCESS;
}
