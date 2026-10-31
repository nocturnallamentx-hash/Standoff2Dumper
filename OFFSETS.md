# Поиск полей для protected IL2CPP dump


Сделан тутор от гптшки, я тут нипричем!


---

## v1.1.0 — Standoff 2 v1.1.0 (обновлено)

Все значения ниже подтверждены на v1.1.0 `libunity.so` (217 MB, ARM64) и
**заменяют** значения v1.0.0 / v31 в остальной части этого документа.

```text
sha256(libunity.so) = ba0966976204fa3f7a2755c9588d32299fe7eb794b712c9f1a444e046cbe7c13
```

### Registrations

```text
ProtectedMetadataVA (metadata base, MV) = 0x1C04200
ProtectedCodeRegistration               = 0xC2AA100
ProtectedMetadataRegistration           = 0xC2AA170
third registration arg                  = 0x31FB7E4
```

setter `0x678C25C` → globals `0xD0B83A8` (codereg), `0xD0B83B0` (metareg), `0xD0B83B8` (third).
loader `0x679CF84` → globals `0xD0B8408` (codereg), `0xD0B8400` (metareg), `0xD0B8410` (metadataBase), `0xD0B8418` (header).

REA-verified registration xref (`codereg+metareg.png` / `coderegxref.png`; ARM64 ADRP+ADD scan, **1 match**):

```text
call-site 0x67C014C:
  ADRP x0,0xC2AA000 ; ADD x0,x0,#0x100  ->  X0 = 0xC2AA100 (CodeRegistration)
  LDR  X1, [0xC8AA010]                  ->  X1 = 0xC2AA170 (MetadataRegistration via slot)
  ADRP/ADD x2,#0x7E4                    ->  X2 = 0x31FB7E4 (third arg)
  B 0x67C01C8 -> B 0x678C25C            ->  setter (stores globals above)
CodeRegistration 0xC2AA100 has exactly 1 code xref @ 0x67C0150 (call-site above).
data: metareg ptr 0xC2AA170 @ 0xEE0510, slot addr 0xC8AA010 @ 0xEE0500, MV base 0x1C04200 @ 0x11ACBB0.
```

### Key runtime pointers

```text
tybase (Il2CppType*[], indexed by type) = 0xC3A65E8   (= metareg + 0x08)
types count (Il2CppType)                = 104242      (metareg + 0x14)
MODULES (CodeGenModule*[])              = 0xC9B01B0   (487 entries)
module name pointer offset              = struct + 0x20
first module                            = 0xC57B6A0 → "AdjustOaid.Android.dll"
```

### Header → table map (addr = MV + hdr[offset])

| Table | hdr | VA | stride | count |
|---|---:|---:|---:|---:|
| STRINGS (NUL-term heap) | `0xC8` | `0x2B248A4` | — | — |
| IMAGES | `0xF8` | `0x30ECF14` | 36 | 487 |
| TYPEDEF records | `0x178` | `0x1E5B1D0` | 82 | 36015 |
| typedef index table | `0x14` | `0x2B21DE4` | u32 | — |
| METHODS | `0x12C` | `0x22981C8` | 32 | 196507 |
| FIELDS | `0x158` | `0x1CD31CC` | 12 | 111549 |
| PARAMS | `0x164` | `0x2EDDE44` | 12 | 179900 |
| PROPERTIES | `0x160` | `0x1C15C6C` | 20 | 41014 |
| fieldOffsets (flat i32[]) | `0x104` | `0x3125A6C` | 4 | — |
| gparams (candidate) | `0x8C` | `0x212C1E0` | 12 | 3559 |

### Counts

```text
images  = 487      typedefs = 36015    methods = 196507
fields  = 111549   params   = 179900   properties = 41014
types (Il2CppType) = 104242
```

### Record layouts (fixed-offset inside a fixed stride)

Record-и v1.1.0 имеют фиксированные смещения внутри фиксированного stride
(produced by a variable-width packing pass; the width descriptor lives in BSS
`0xD0B8424` and is filled at runtime). Смещения ниже подтверждены empirically:
name/token по строке-индексу, counts/starts по global-sum / prefix-sum анализу.

```text
IMAGE (36B)
  name       u32 @ +0
  typeCount  u32 @ +12            (Σ over 487 = 36015)
  typeStart          = cumulative sum of typeCount in table order

TYPEDEF (82B)
  fieldCount    u16 @ +0          (Σ = 111549)
  name          u32 @ +6
  fieldStart    i32 @ +18         (sentinel -1 when fieldCount == 0)
  methodStart   i32 @ +30         (sentinel -1 when methodCount == 0)
  ns            u32 @ +34
  propertyCount u16 @ +40         (Σ = 41014)
  methodCount   u16 @ +42         (Σ = 196507)
  propertyStart i32 @ +62         (prefix-sum of propertyCount)
  token         u32 @ +72         (0x02000000 | rid)
  parent / declaringType / flags / bitfield / gc  → TBD (width-descriptor)

METHOD (32B)
  paramCount  u16 @ +4            (Σ = 179900)
  name        u32 @ +18
  token       u32 @ +24           (0x06000000 | rid)
  paramStart  i32 @ +28           (sentinel -1 when paramCount == 0)
  rtype / flags / gc  → TBD (width-descriptor)

FIELD (12B)
  name    u32 @ +0
  token   u32 @ +4                (0x04000000 | rid)
  type    u32 @ +8                (Il2CppType index < 104242)

PARAM (12B)
  type    u32 @ +0                (Il2CppType index)
  name    u32 @ +4
  token   u32 @ +8                (0x08000000 | rid)

PROPERTY (20B)
  get     i32 @ +0                (method index rel. to type methodStart; -1 = none)
  name    u32 @ +4
  attrs   u32 @ +8
  token   u32 @ +12               (0x17000000 | rid)
  set     i32 @ +16               (method index; -1 = none)
```

### String literals (v1.1.0)

```text
string-literal DATA = metadataBase + hdr[0xC8] = 0x2B248A4
```

Строки в v1.1.0 — plain NUL-terminated heap (подтверждено прямым чтением:
`"Bolt.Api.dll"`, `".ctor"`, `"NullableFlags"` и т.д. по `STRINGS + index`),
поэтому length = `strlen`; отдельная offsets-таблица (`length = off[i+1]-off[i]`)
для базового чтения не нужна. offsets-таблица / count для `stringliteral.json`
— ещё не пиннены (см. «Осталось»).

### Осталось (не подтверждено / требует доработки)

- **Il2CppType (24B)** — kind/data encoding изменился против v1.0.0; `typename()`
  в `huawei_dump.py` нужно пере-вывести. Защитный дескриптор (см. «Protected Il2CppType
  descriptor» ниже) — `byte1 = Il2CppTypeEnum`, `data @ +8`, но точный pack под v1.1.0
  не подтверждён на известных ground-truth типах.
- **fieldOffsets** — flat i32[] найден (`hdr+0x104 → 0x3125A6C`, первые значения
  `[8,10,12,14,…]`), но per-type start-index (typedef) или pointer-table не пиннены
  (v1.0.0 использовал pointer-table `0xC303F68`, `e.ptr(OFFSETS+ti*8)`).
- **gparams** — `hdr+0x8C → 0x212C1E0` (3559×12) кандидат, но name-index не
  разбросывается как ожидалось; нужен точный layout.
- **module struct** — name `@ +0x20` подтверждён; methodPointers / fieldOffsetPtr
  (v1.0.0 `ptr(p)` / `ptr(p+0x70)`) не пиннены под новый layout.
- **method rtype / flags / gc**, **typedef parent / declaringType / flags / bitfield / gc**
  — поля внутри packed-record; нужны точные смещения (width-descriptor `0xD0B8424`).

Для обновления после новой версии сначала перепроверять (порядок из §9):
`ProtectedMetadataVA`, `ProtectedCodeRegistration`, `ProtectedMetadataRegistration`,
string-literal data/header, затем image/typedef/method/field/param/property record layouts.

---

## 1. Protected metadata base

Ищи строку `global-metadata.dat` и xref на код, который загружает/декодирует metadata. В этой сборке цепочка приводит к `initialize_protected_metadata` по `0x639C940`.

В `initialize_protected_metadata` после вызова loader-а возвращаемый указатель сохраняется в глобал и дальше из header читаются count-поля. Это и есть base protected metadata header.

Текущая база:

```text
ProtectedMetadataVA = 0x1B60480
```

Паттерн для Поиска Codegenreg + Metadatareg или как там крч - ? ? ? ? ? ? ? 91 ? ? ? F9 C0 03 5F D6 ? ? ? D1 ? ? ? A9 ? ? ? AA  (кодерег метарег.пнг) 1 совпадение - метадата поинтер

Быстрая проверка:

```text
header + 0x14C -> imagesCount          = 463
header + 0x154 -> typeDefinitionsCount = 33762
header + 0x100 -> genericContainersCount = 4021
```

Как найти offsets после обновления:

1. Открыть `initialize_protected_metadata`.
2. Найти `LDR W?, [X19,#imm]` или аналогичные чтения из указателя на header.
3. Посмотреть, куда сохраняется значение и какой consumer потом использует его как count.
4. Подтвердить count по соседним metadata-функциям: image/type/method definition getters.
5. Не переносить offset только по похожему числу: проверять минимум двумя consumer-функциями.

В текущем binary:

```text
initialize_protected_metadata:
[header + 0x14C] -> images count
[header + 0x094] -> еще один metadata count, используемый при init
[header + 0x154] -> typeDefinitions count
[header + 0x100] -> genericContainers count
[header + 0x0D0] -> еще один protected table count
[header + 0x124] -> count для отдельной runtime table
```

## 2. String literals

Критичные поля для полного `stringliteral.json`:

```text
ProtectedStringLiteralOffsetsField      = 0x160
ProtectedStringLiteralDataField         = 0x138
ProtectedStringLiteralCountField        = 0x0FC
ProtectedStringLiteralOffsetsCountField = 0x044
```

Как их найти:

1. Найти функцию, которая создаёт managed string из metadata. В этой сборке путь проходит через `sub_639CBA8`.
2. В ветке string-literal она получает индекс literal.
3. Затем берётся таблица offsets:

```text
header + 0x160
```

4. Для literal `i` читаются два соседних offset-а:

```text
offset[i]
offset[i + 1]
```

5. Длина literal определяется как:

```text
offset[i + 1] - offset[i]
```

6. Данные начинаются от:

```text
metadataBase + *(int32_t *)(header + 0x138)
```

7. Указатель на UTF-8 bytes для literal `i`:

```text
metadataBase
+ *(int32_t *)(header + 0x138)
+ offset[i]
```

В текущем binary это видно в `sub_639CBA8`: сначала вычисляется адрес пары offsets через `header + 0x160`, затем bytes берутся через `header + 0x138`.

Для обновления версии ищи именно этот data-flow, а не сигнатуру конкретной функции.

## 3. Images и DLL names

DLL/image names лучше восстанавливать через image definitions, а не искать строки `.dll` отдельно.

Текущая consumer-функция:

```text
metadata_get_image_definition = 0x639D37C
```

Она вычисляет запись image definition как:

```text
metadataBase
+ *(int32_t *)(header + 0x0BC)
+ imageStride * imageIndex
```

где stride выводится из соседних header-полей/count.

Имя image затем разрешается через string table base:

```text
metadataBase + *(int32_t *)(header + 0x150) + nameIndex
```

Проверка правильности: получаются реальные имена вроде:

```text
Assembly-CSharp.dll
UnityEngine.dll
Axlebolt.Standoff.*.dll
```

Если дампер находит images, но не codegen modules, нормализовать ключи в двух вариантах:

```text
Name.dll
Name
```

и использовать case-insensitive lookup.

## 4. CodeRegistration

Текущий адрес:

```text
ProtectedCodeRegistration = 0xC2AA100
```

(v1.1.0 confirmed; v1.0.0 было `0xB7C32E0`. Layout/count-checks ниже — старый v1.0.0 reference, см. блок v1.1.0 вверху.)

Проверочные поля:

```text
+0x44 codeGenModulesCount          = 463
+0x54 invokerPointersCount         = 33045
+0x58 genericMethodPointersCount   = 224501
+0x50 unresolvedVirtualCallCount   = 8399
```

Текущий layout, который использует `ProtectedLayout.cs`:

```text
+0x00 unresolvedVirtualCallPointers
+0x08 reversePInvokeWrappers
+0x10 unresolvedInstanceCallPointers
+0x18 unresolvedStaticCallPointers
+0x28 invokerPointers
+0x30 codeGenModules
+0x40 interopDataCount
+0x44 codeGenModulesCount
+0x48 genericAdjustorThunks
+0x50 unresolvedVirtualCallCount
+0x54 invokerPointersCount
+0x58 genericMethodPointersCount
+0x60 interopData
+0x68 reversePInvokeWrapperCount
+0x70 genericMethodPointers
```

Как найти после обновления:

1. Найти IL2CPP registration/init path.
2. Найти массив codegen module pointers.
3. Кандидат на `codeGenModulesCount` должен совпасть с `imagesCount` или быть очень близок по смыслу; в этой сборке оба равны 463.
4. Указатель рядом должен вести в массив 64-bit pointers.
5. Каждый element массива должен вести на структуру module.
6. В структуре module найти указатель на имя и подтвердить чтением нескольких `.dll` names.
7. После этого размечать остальные поля по consumer-функциям, а не по позиции в старой версии.

## 5. Il2CppCodeGenModule

Текущий protected layout:

```text
+0x08 methodPointerCount
+0x18 rgctxsCount
+0x20 adjustorThunks
+0x30 methodPointers
+0x38 rgctxRanges
+0x40 reversePInvokeWrapperCount
+0x58 rgctxRangesCount
+0x60 invokerIndices
+0x68 adjustorThunkCount
+0x70 reversePInvokeWrapperIndices
+0x78 rgctxs
+0x80 moduleName
```

Как проверить module struct:

1. Взять один pointer из `CodeRegistration.codeGenModules`.
2. `module + 0x80` должен быть pointer на null-terminated DLL name.
3. `module + 0x08` должен быть реалистичным method count.
4. `module + 0x30` должен указывать на массив executable pointers либо runtime-relocated entries.
5. Для нескольких разных modules структура должна интерпретироваться одинаково.

Если `methodPointers` попадают в `.bss`, offline dump может видеть нули до runtime init. Это не означает, что module layout неверен.

## 6. MetadataRegistration

Текущий адрес:

```text
ProtectedMetadataRegistration = 0xC2AA170
```

(v1.1.0 confirmed; v1.0.0 было `0xB7C3358`. Layout/count-checks ниже — старый v1.0.0 reference, см. блок v1.1.0 вверху.)

Проверка:

```text
+0x00 genericMethodTableCount = 225450
+0x20 genericInstsCount       = 28847
+0x30 typesCount              = 98641
+0x40 methodSpecsCount        = 278565
+0x58 genericClassesCount     = 37557
```

Текущий layout:

```text
+0x00 genericMethodTableCount
+0x04 fieldOffsetsCount
+0x08 genericClasses
+0x18 genericInsts
+0x20 genericInstsCount
+0x28 typeDefinitionsSizes
+0x30 typesCount
+0x34 typeDefinitionsSizesCount
+0x40 methodSpecsCount
+0x48 types
+0x50 methodSpecs
+0x58 genericClassesCount
+0x60 genericMethodTable
+0x68 fieldOffsets
```

Как найти:

1. От registration function проследить второй большой static block рядом с CodeRegistration.
2. Найти `types` через consumer, который индексирует массив pointer-ов на `Il2CppType`.
3. `typesCount` должен согласовываться с количеством доступных type entries.
4. Найти `methodSpecs` через generic-method resolution path.
5. Найти `genericMethodTable` через код, который связывает method spec с generic method pointer/invoker.
6. Найти `fieldOffsets` через код, который возвращает runtime field offset для type/field.
7. После идентификации pointer-а и count-а проверить оба как пару.

## 7. MethodSpec и GenericMethodTable

Текущий layout:

```text
Il2CppMethodSpec, size 0x0C:
+0x00 classIndexIndex
+0x04 methodIndexIndex
+0x08 methodDefinitionIndex

GenericMethodTable entry, size 0x10:
+0x00 adjustorThunkIndex
+0x04 invokerIndex
+0x08 methodPointerIndex
+0x0C methodSpecIndex
```

Проверка:

```text
methodSpecIndex < methodSpecsCount
methodDefinitionIndex >= 0
classIndexIndex == -1 или < genericInstsCount
methodIndexIndex == -1 или < genericInstsCount
methodPointerIndex < genericMethodPointersCount
```

Если эти ограничения массово не выполняются, layout или stride неверный.

## 8. Il2CppType bits

Текущий decode:

```text
attrs    = bits & 0xFFFF
byref    = (bits >> 17) & 1
type     = (bits >> 18) & 0xFF
num_mods = (bits >> 26) & 0x1F
pinned   = (bits >> 31) & 1
```

Тип определяется по `type` после сдвига на 18.

## 9. Что обязательно обновлять после новой версии

Сначала проверить только:

```text
ProtectedMetadataVA
ProtectedCodeRegistration
ProtectedMetadataRegistration
ProtectedStringLiteralOffsetsField
ProtectedStringLiteralDataField
ProtectedStringLiteralCountField
ProtectedStringLiteralOffsetsCountField
```

Если dump всё ещё некорректный, затем проверять:

```text
CodeRegistration layout
MetadataRegistration layout
Il2CppCodeGenModule layout
image definition stride/fields
MethodSpec layout
GenericMethodTable layout
Il2CppType bit layout
```

## 10. Минимальный порядок проверки в IDA

```text
1. global-metadata.dat -> loader -> protected metadata base
2. initialize_protected_metadata -> header counts
3. string creation path -> string literal offsets/data
4. metadata_get_image_definition -> images/DLL names
5. registration init -> CodeRegistration
6. codeGenModules array -> Il2CppCodeGenModule fields
7. generic method resolution -> MetadataRegistration/method specs
8. field offset resolver -> fieldOffsets
9. проверить counts и pointer ranges
10. только после этого менять config/layout в dumper
```

Для pointer-полей обязательно проверять, что адрес попадает в ожидаемый segment:

```text
code pointers  -> .text / executable mapping
string/data    -> .rodata / metadata mapping
runtime arrays -> .data/.bss или mapped runtime memory
```

Если count выглядит правдоподобно, но pointer ведёт в мусор, пара `pointer + count` определена неверно.

## Default values / constants (protected v31)

Runtime accessors `sub_6342F9C` and `sub_6343FC8` confirm the protected default-value tables used by fields and optional parameters.

| Section | Header field(s) | Value in this build | Protected record |
|---|---:|---:|---|
| Field default values offset | `hdr + 0x134` | `0x00C4C820` | `{ dataIndex, fieldIndex, typeIndex }` |
| Field default values packed size | `hdr + 0x84` | `0x0003FEB8` | 21818 × 12 bytes |
| Field default values count | `hdr + 0x2C` | `21818` | — |
| Parameter default values offset | `hdr + 0x60` | `0x00CA74F8` | `{ parameterIndex, dataIndex, typeIndex }` |
| Parameter default values packed size | `hdr + 0xB4` | `0x0000A380` | 3488 × 12 bytes |
| Parameter default values count | `hdr + 0xBC` | `3488` | — |
| Shared default-value data offset | `hdr + 0x154` | `0x0014C9DC` | raw v31 constant blob |
| Shared default-value data end | parameter table start | `0x0018081C` | size `0x33E40` |

Stock reconstruction order:

```text
Il2CppFieldDefaultValue     = { fieldIndex, typeIndex, dataIndex }
Il2CppParameterDefaultValue = { parameterIndex, typeIndex, dataIndex }
```

`dataIndex == -1` is preserved and represents a null/no-payload default where applicable; it must not be used as a reason to discard the `const`/optional metadata row.

## ImageDefinition (protected v31)

`sub_B2F5B40` expands each 36-byte protected image record to the logical 40-byte image definition. For this build the protected logical field order is:

```text
+0x00 customAttributeCount
+0x04 entryPointIndex
+0x08 typeStart               (packed TypeDefinitionIndex)
+0x0C customAttributeStart
+0x10 typeCount
+0x14 token
+0x18 exportedTypeStart       (packed TypeDefinitionIndex)
+0x1C nameIndex
+0x20 exportedTypeCount
+0x24 assemblyIndex
```

This restores per-image custom-attribute ranges and exported-type ranges in the rebuilt stock metadata instead of zeroing them.

## Protected Il2CppType descriptor — corrected

```text
DWORD @ Il2CppType + 0:
  bit  6 (byte0) = valuetype
  bit  7 (byte0) = byref
  byte1           = Il2CppTypeEnum
  bytes2..3       = attrs (uint16)
QWORD @ Il2CppType + 8 = data
```

Do **not** read protected byte0 `0x40` as `FIELD_ATTRIBUTE_LITERAL`: it is the protected `valuetype` flag. The real field/parameter attrs are the high 16 bits of the protected descriptor DWORD. This was the source of the old mass-false-`const` output.
