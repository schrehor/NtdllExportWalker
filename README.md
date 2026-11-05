# NtdllExportWalker

A small Windows tool for walking NTDLL's exports, written in C.

Finds NTDLL through the current process's PEB loader list, then reads its PE export tables manually. Prints export names, ordinals, RVAs and addresses, with optional comparisons against the Windows API.

## Build target

Windows x64 or x86. Visual Studio with the v145 C/C++ toolset and Windows SDK.

Open `NtdllExportWalker.slnx` and build Debug or Release for x64 or Win32.

## Usage

```powershell
.\x64\Release\NtdllExportWalker.exe
.\x64\Release\NtdllExportWalker.exe --base --compare
.\x64\Release\NtdllExportWalker.exe --name NtClose --compare
.\x64\Release\NtdllExportWalker.exe --all
```

Lists named `Nt` and `Zw` exports by default. `--all` includes the other named exports. Exported functions are never called.

The loader structures are Windows internals and can change between versions.
