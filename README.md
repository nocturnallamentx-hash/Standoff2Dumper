# Standoff 2 Dumper — v1.1.0 fork

Offline dumper for the protected IL2CPP build of Standoff 2 (Huawei / `libunity.so` path).
It rebuilds the protected metadata directly from the ELF, with no server session required,
and produces a full `dump.cs`, `il2cpp.h`, `script.json` and a `DummyDll/` folder with **487**
reconstructed assemblies (36015 types, 196507 methods, 111549 fields).

Everything that previously required the axent.cc server session for the Huawei build now
runs 100% locally in Python (`Il2CppDumper/huawei_dump.py`). The Google build path still
requires the server session (unchanged from the original project).

## Verified on

```text
libunity.so sha256 = ba0966976204fa3f7a2755c9588d32299fe7eb794b712c9f1a444e046cbe7c13
images 487 | typedefs 36015 | methods 196507 | fields 111549 | params 179900 | properties 41014
```

Resolved record layouts (v1.1.0, empirically pinned and validated):

| Field | Slot | Notes |
|---|---|---|
| method flags | u16 @ +22 | MethodAttributes; access = low 3 bits. `.cctor` = 0x1891, `.ctor` = 0x1886 |
| method gc | u16 @ +14 | 0xFFFF = not generic |
| typedef parent | u32 @ +26 | Il2CppType index (e.g. `ApplicationException : System.Exception`) |
| field type | u32 @ +8 | Il2CppType index |
| fieldOffsets | flat i32[] @ `0x3125A6C` | indexed by global field index |

Full offset-by-offset documentation: [OFFSETS.md](OFFSETS.md).

## Output

```text
dump.cs                  full IL2CPP dump, Il2CppDumper format
il2cpp.h                 C headers, packed structs ready for Ghidra/IDA
script.json              script method list
DummyDll/*.dll           487 reconstructed .NET assemblies (Mono.Cecil)
huawei.manifest.jsonl    intermediate manifest for the DummyDll exporter
dump.info.json           run statistics
```

Sample of the generated hierarchy:

```text
GameObject : UnityEngine.Object
MonoBehaviour : UnityEngine.Behaviour
ScriptableObject : UnityEngine.Object
Transform : UnityEngine.Component
ApplicationException : System.Exception
MemoryStream : System.IO.Stream
```

## Build

```bat
build-release.bat
```

Requires .NET 7 SDK (and Python 3 on PATH for the Huawei dump).

## Usage

```text
Il2CppDumper <libunity.so> [output-dir] --version huawei
```

Or run the Python dumper directly (no server, no license, no session):

```bash
python3 huawei_dump.py libunity.so -o ./out --structs --dummy-manifest
```

Then generate the DLLs from the manifest (see `HuaweiDummyAssemblyExporter`).

## Project structure

- `Il2CppDumper/huawei_dump.py` — offline parser for the protected metadata in `libunity.so`
- `Il2CppDumper/HuaweiMetadataDumper.cs` — orchestrates the Python parser (shell-out)
- `Il2CppDumper/HuaweiDummyAssemblyExporter.cs` — DummyDLL export from the manifest (Mono.Cecil)
- `Il2CppDumper/AxentApi.cs` — original session/licence gate (Google path only)
- `Il2CppDumper/` — the rest of the original Il2CppDumper engine (unchanged)

## Credits

This v1.1.0 fork (offline Huawei dumper, record layouts, DummyDLL pipeline):
**nocturnallamentx-hash**

### Contact / Community

- Telegram group: [t.me/n0cDll](https://t.me/n0cDll)
- WhatsApp group: [JjJrvkd7l3ZLaXM6RewKVg](https://chat.whatsapp.com/JjJrvkd7l3ZLaXM6RewKVg?s=cl&p=a&iam=2)

### Original project

This build is based on the protected-metadata research of the original
Standoff 2 dumper project and [Perfare's Il2CppDumper](https://github.com/Perfare/Il2CppDumper).

## License

Same license as the original project — see [LICENSE](LICENSE).
