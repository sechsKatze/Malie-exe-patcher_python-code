Malie-exe-patcher_python-code
====
This tool patches Malie engine executables by injecting a modified EXEC.bin directly into the EXE file.

Normally, replacing EXEC.bin using tools like Resource Hacker can corrupt the .rsrc section and break the executable when the file size changes.
This patcher solves that problem by creating a new section in the EXE and redirecting the resource entry, allowing larger EXEC.bin files to be injected safely.

Note:
This patcher only works on unpacked executables.  
If the executable is still protected by DRM, the patch may fail because the internal PE structure or resource access can be altered by the protection.

Additionally, while this tool was designed for Karin games (Karin Entertainment(Otome)/ Karin Chat Noir Omega(BL)) that use the Malie engine, other Malie-based games may have different EXE structures and may not be compatible.

Features
====
1. Inject EXEC.bin directly into a Malie engine executable
2. Prevents .rsrc corruption caused by Resource Hacker replacement
3. Automatically:
- overwrites in-place if size allows
- creates a new PE section if the file becomes larger
4. Recalculates the PE checksum
5. Works with Karin Entertainment Malie engine games

Compatibility
====
This patcher is designed for Karin Entertainment(BL : Karin Chat noir Omega) games using the Malie engine, including:

- Omerta -Chinmoku no Okite- (オメルタ -沈黙の掟-) ※BL
- Omerta CODE:TYCOON (オメルタ CODE:TYCOON) ※BL
- Omega Vampire (オメガヴァンパイア) ※BL
- Danzai no Maria -The Exorcism of Maria- (断罪のマリア　THE EXORCISM OF MARIA)
- Zettai Meikyuu Grimm -Nanatsu no Kagi to Rakuen no Otome- (絶対迷宮グリム -七つの鍵と楽園の乙女-)

Usage
====
Place the executable and EXEC.bin in the same directory and run:
```bash
python malie_exe_patcher.py original.exe EXEC.bin patched.exe
```

Example:
```bash
python malie_exe_patcher.py original.exe EXEC.bin patched.exe
```

Why this tool exists
====
Replacing EXEC.bin through normal resource editing tools often causes:
 1. resource table corruption
 2. broken .rsrc alignment
 3. EXE crash on launch

This tool avoids those issues by patching the PE structure directly.


Requirements
====
- Python 3.x

Notes
====
This tool modifies PE structure directly.
Always keep a backup of the original executable before patching.
