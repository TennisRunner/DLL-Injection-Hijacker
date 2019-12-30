# DLL-Injection-Hijacker
Parses a DLL's dos and pe header. Then creates a new section called .temp and writes the dll file name it should load, along with the opcodes to load it. It then changes the entry point to that new section, adds a relocation entry, and writes a jump back to the original OEP.
