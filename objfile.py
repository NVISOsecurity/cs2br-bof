from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import List, Sequence, Tuple
from structex.basetypes import Struct, StructLayout, int16_t, uint16_t, uint32_t, uint64_t, uint8_t
from structex.common import IMemory
from structex.fields import Array, FixedString, Instance, Primitive
from structex.memory import BufferMemory, CachedMemory

# Structs & Types


class MachineType(IntEnum):
    IMAGE_FILE_MACHINE_I386 = 0x014c
    IMAGE_FILE_MACHINE_IA64 = 0x0200
    IMAGE_FILE_MACHINE_AMD64 = 0x8664


class ImageCharacteristics(IntFlag):
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000


class coff_file_header(Struct):
    _layout: StructLayout = StructLayout.Sequential

    _machine: int = Primitive(uint16_t)
    NumberOfSections: int = Primitive(uint16_t)
    TimeDateStamp: int = Primitive(uint32_t)
    PointerToSymbolTable: int = Primitive(uint32_t)
    NumberOfSymbols: int = Primitive(uint32_t)
    SizeOfOptionalHeader: int = Primitive(uint16_t)
    _characteristics: int = Primitive(uint16_t)

    @property
    def Machine(self) -> MachineType:
        return MachineType(self._machine)

    @property
    def Characteristics(self) -> ImageCharacteristics:
        return ImageCharacteristics(self._characteristics)

    @property
    def sections(self) -> Sequence['coff_sect']:
        return [
            coff_sect(self, self.mem, coff_file_header.get_size() +
                      coff_sect.get_size() * i)
            for i in range(self.NumberOfSections)
        ]

    @property
    def symbols(self) -> Sequence['coff_sym']:
        return [
            coff_sym(i, self, self.mem, self.PointerToSymbolTable +
                     coff_sym.get_size() * i)
            for i in range(self.NumberOfSymbols)
        ]

    @property
    def stringtable(self) -> 'coff_strings':
        return coff_strings(self, self.mem, self.PointerToSymbolTable + self.NumberOfSymbols * coff_sym.get_size())

    def get_symbol_by_name(self, name: str):
        return next(filter(lambda s: s.Name == name, self.symbols), None)

    def get_section_definitions(self) -> Sequence['SectionDefintion']:
        _symbols = self.symbols
        _sections = self.sections

        defs = []
        for i in range(len(_symbols) - 1):
            if _symbols[i].NumberOfAuxSymbols > 0 and _symbols[i].StorageClass == StorageClassType.IMAGE_SYM_CLASS_STATIC:
                defs.append(
                    SectionDefintion(
                        _symbols[i],
                        i,
                        [
                            coff_sym_aux_secdef(self.mem, s.offset) for s in _symbols[i+1: i + 1 + _symbols[i].NumberOfAuxSymbols]
                        ],
                        next(filter(lambda s: s.Name == _symbols[i].Name, _sections), None)
                    )
                )

        return defs

    def update_string_refs(self, idx: int, delta: int):
        for sect in self.sections:
            if not sect.IsShortName:
                _idx = int(sect._name[1:])
                if _idx > idx:
                    sect._name = f"/{_idx + delta}"

        for sym in self.symbols:
            if not sym.IsShortName and sym.NameIndex >= idx:
                sym._nameIndices[1] = sym._nameIndices[1] + delta
            


@dataclass
class SectionDefintion:
    sectionSymbol: 'coff_sym'
    sectionSymbolIdx: int
    sectionAuxSymbols: Sequence['coff_sym_aux_secdef']
    section: 'coff_sect'


class SectionCharacteristics(IntFlag):
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008


class coff_sect(Struct):
    _layout: StructLayout = StructLayout.Sequential

    _name: str = FixedString(8)
    VirtualSize: int = Primitive(uint32_t)
    VirtualAddress: int = Primitive(uint32_t)
    SizeOfRawData: int = Primitive(uint32_t)
    PointerToRawData: int = Primitive(uint32_t)
    PointerToRelocations: int = Primitive(uint32_t)
    PointerToLineNumbers: int = Primitive(uint32_t)
    NumberOfRelocations: int = Primitive(uint16_t)
    NumberOfLinenumbers: int = Primitive(uint16_t)
    _characteristics: int = Primitive(uint32_t)

    def __init__(self, filehdr: coff_file_header, mem: IMemory, offset: int) -> None:
        super().__init__(mem, offset)
        self._filehdr = filehdr

    @property
    def IsShortName(self)->bool:
        return not self._name.startswith("/")

    @property
    def Name(self) -> str:
        if not self.IsShortName:
            return self._filehdr.stringtable.get_string_from_offset(int(self._name[1:]))
        else:
            return self._name

    @Name.setter
    def Name(self, name):
        if len(name) > 8:
            offset = self._filehdr.stringtable.append_string(name)
            self._name = f"/{offset}"
        else:
            self._name = name
        

    @property
    def Characteristics(self) -> SectionCharacteristics:
        return SectionCharacteristics(self._characteristics)

    @property
    def relocations(self) -> Sequence['coff_reloc']:
        return [coff_reloc(self._filehdr, self.mem, self.PointerToRelocations + i * coff_reloc.get_size()) for i in range(self.NumberOfRelocations)]

    def __repr__(self) -> str:
        return f"[Section@{self.offset}] {self.Name} {hex(self.PointerToRawData)}-{hex(self.PointerToRawData+self.SizeOfRawData)} ({self.SizeOfRawData} bytes)"

    def __str__(self) -> str:
        return self.__repr__()


class RelocType64(IntEnum):
    IMAGE_REL_AMD64_ABSOLUTE = 0x0000
    IMAGE_REL_AMD64_ADDR64 = 0x0001
    IMAGE_REL_AMD64_ADDR32 = 0x0002
    IMAGE_REL_AMD64_ADDR32NB = 0x0003
    IMAGE_REL_AMD64_REL32 = 0x0004
    IMAGE_REL_AMD64_REL32_1 = 0x0005
    IMAGE_REL_AMD64_REL32_2 = 0x0006
    IMAGE_REL_AMD64_REL32_3 = 0x0007
    IMAGE_REL_AMD64_REL32_4 = 0x0008
    IMAGE_REL_AMD64_REL32_5 = 0x0009
    IMAGE_REL_AMD64_SECTION = 0x000A
    IMAGE_REL_AMD64_SECREL = 0x000B
    IMAGE_REL_AMD64_SECREL7 = 0x000C
    IMAGE_REL_AMD64_TOKEN = 0x000D
    IMAGE_REL_AMD64_SREL32 = 0x000E
    IMAGE_REL_AMD64_PAIR = 0x000F
    IMAGE_REL_AMD64_SSPAN32 = 0x0010


class RelocType86(IntEnum):
    IMAGE_REL_I386_ABSOLUTE = 0x0000
    IMAGE_REL_I386_DIR16 = 0x0001
    IMAGE_REL_I386_REL16 = 0x0002
    IMAGE_REL_I386_DIR32 = 0x0006
    IMAGE_REL_I386_DIR32NB = 0x0007
    IMAGE_REL_I386_SEG12 = 0x0009
    IMAGE_REL_I386_SECTION = 0x000A
    IMAGE_REL_I386_SECREL = 0x000B
    IMAGE_REL_I386_TOKEN = 0x000C
    IMAGE_REL_I386_SECREL7 = 0x000D
    IMAGE_REL_I386_REL32 = 0x0014


class coff_reloc(Struct):
    _layout: StructLayout = StructLayout.Sequential
    VirtualAddress: int = Primitive(uint32_t)
    SymbolTableIndex: int = Primitive(uint32_t)
    _type: int = Primitive(uint16_t)

    def __init__(self, filehdr: coff_file_header, mem: IMemory, offset: int) -> None:
        super().__init__(mem, offset)
        self._filehdr = filehdr

    @property
    def SymbolTableEntry(self) -> 'coff_sym':
        return self._filehdr.symbols[self.SymbolTableIndex]

    @property
    def Type64(self) -> RelocType64:
        return RelocType64(self._type)

    @property
    def Type86(self) -> RelocType86:
        return RelocType86(self._type)

    def __repr__(self) -> str:
        if self._filehdr.Machine == MachineType.IMAGE_FILE_MACHINE_AMD64:
            return f'[Reloc@{self.offset}] Symbol "{self.SymbolTableEntry.Name}", type {self.Type64.name} (x64)'
        elif self._filehdr.Machine == MachineType.IMAGE_FILE_MACHINE_I386:
            return f'[Reloc@{self.offset}] Symbol "{self.SymbolTableEntry.Name}", type {self.Type86.name} (x86)'
        else:
            return f'[Reloc@{self.offset}] Symbol "{self.SymbolTableEntry.Name}", unknown type'


class StorageClassType(IntEnum):
    # A special symbol that represents the end of function, for debugging purposes.
    IMAGE_SYM_CLASS_END_OF_FUNCTION = 0xFF
    IMAGE_SYM_CLASS_NULL = 0  # No assigned storage class.
    # The automatic (stack) variable. The Value field specifies the stack frame offset.
    IMAGE_SYM_CLASS_AUTOMATIC = 1
    # A value that Microsoft tools use for external symbols. The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0). If the section number is not zero, then the Value field specifies the offset within the section.
    IMAGE_SYM_CLASS_EXTERNAL = 2
    # The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
    IMAGE_SYM_CLASS_STATIC = 3
    # A register variable. The Value field specifies the register number.
    IMAGE_SYM_CLASS_REGISTER = 4
    IMAGE_SYM_CLASS_EXTERNAL_DEF = 5  # A symbol that is defined externally.
    # A code label that is defined within the module. The Value field specifies the offset of the symbol within the section.
    IMAGE_SYM_CLASS_LABEL = 6
    # A reference to a code label that is not defined.
    IMAGE_SYM_CLASS_UNDEFINED_LABEL = 7
    # The structure member. The Value field specifies the n th member.
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8
    # A formal argument (parameter) of a function. The Value field specifies the n th argument.
    IMAGE_SYM_CLASS_ARGUMENT = 9
    IMAGE_SYM_CLASS_STRUCT_TAG = 10  # The structure tag-name entry.
    # A union member. The Value field specifies the n th member.
    IMAGE_SYM_CLASS_MEMBER_OF_UNION = 11
    IMAGE_SYM_CLASS_UNION_TAG = 12  # The Union tag-name entry.
    IMAGE_SYM_CLASS_TYPE_DEFINITION = 13  # A Typedef entry.
    IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14  # A static data declaration.
    IMAGE_SYM_CLASS_ENUM_TAG = 15  # An enumerated type tagname entry.
    # A member of an enumeration. The Value field specifies the n th member.
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 16
    IMAGE_SYM_CLASS_REGISTER_PARAM = 17  # A register parameter.
    # A bit-field reference. The Value field specifies the n th bit in the bit field.
    IMAGE_SYM_CLASS_BIT_FIELD = 18
    # A .bb (beginning of block) or .eb (end of block) record. The Value field is the relocatable address of the code location.
    IMAGE_SYM_CLASS_BLOCK = 100
    # A value that Microsoft tools use for symbol records that define the extent of a function: begin function (.bf ), end function ( .ef ), and lines in function ( .lf ). For .lf records, the Value field gives the number of source lines in the function. For .ef records, the Value field gives the size of the function code.
    IMAGE_SYM_CLASS_FUNCTION = 101
    IMAGE_SYM_CLASS_END_OF_STRUCT = 102  # An end-of-structure entry.
    # A value that Microsoft tools, as well as traditional COFF format, use for the source-file symbol record. The symbol is followed by auxiliary records that name the file.
    IMAGE_SYM_CLASS_FILE = 103
    # A definition of a section (Microsoft tools use STATIC storage class instead).
    IMAGE_SYM_CLASS_SECTION = 104
    # A weak external. For more information, see Auxiliary Format 3: Weak Externals.
    IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105
    # A CLR token symbol. The name is an ASCII string that consists of the hexadecimal value of the token. For more information, see CLR Token Definition (Object Only).
    IMAGE_SYM_CLASS_CLR_TOKEN = 107


class SymbolBaseType(IntEnum):
    # No type information or unknown base type. Microsoft tools use this setting
    IMAGE_SYM_TYPE_NULL = 0
    IMAGE_SYM_TYPE_VOID = 1  # No valid type; used with void pointers and functions
    IMAGE_SYM_TYPE_CHAR = 2  # A character (signed byte)
    IMAGE_SYM_TYPE_SHORT = 3  # A 2-byte signed integer
    # A natural integer type (normally 4 bytes in Windows)
    IMAGE_SYM_TYPE_INT = 4
    IMAGE_SYM_TYPE_LONG = 5  # A 4-byte signed integer
    IMAGE_SYM_TYPE_FLOAT = 6  # A 4-byte floating-point number
    IMAGE_SYM_TYPE_DOUBLE = 7  # An 8-byte floating-point number
    IMAGE_SYM_TYPE_STRUCT = 8  # A structure
    IMAGE_SYM_TYPE_UNION = 9  # A union
    IMAGE_SYM_TYPE_ENUM = 10  # An enumerated type
    IMAGE_SYM_TYPE_MOE = 11  # A member of enumeration (a specific value)
    IMAGE_SYM_TYPE_BYTE = 12  # A byte; unsigned 1-byte integer
    IMAGE_SYM_TYPE_WORD = 13  # A word; unsigned 2-byte integer
    # An unsigned integer of natural size (normally, 4 bytes)
    IMAGE_SYM_TYPE_UINT = 14
    IMAGE_SYM_TYPE_DWORD = 15  # An unsigned 4-byte integer


class SymbolTargetType(IntEnum):
    # No derived type; the symbol is a simple scalar variable.
    IMAGE_SYM_DTYPE_NULL = 0
    IMAGE_SYM_DTYPE_POINTER = 1  # The symbol is a pointer to base type.
    # The symbol is a function that returns a base type.
    IMAGE_SYM_DTYPE_FUNCTION = 2
    IMAGE_SYM_DTYPE_ARRAY = 3  # The symbol is an array of base type.


class coff_sym(Struct):
    _layout: StructLayout = StructLayout.Fixed
    _size = 18

    ShortName: str = FixedString(8, offset=0)
    _nameIndices: Sequence[int] = Array(uint32_t, count=2, offset=0)

    Value: int = Primitive(uint32_t, offset=8)
    SectionNumber: int = Primitive(int16_t, offset=12)
    _type: int = Primitive(uint16_t, offset=14)
    _storageClass: int = Primitive(uint8_t, offset=16)
    NumberOfAuxSymbols: int = Primitive(uint8_t, offset=17)

    def __init__(self, index: int, filehdr: coff_file_header, mem: IMemory, offset: int) -> None:
        super().__init__(mem, offset)
        self._filehdr = filehdr
        self._index = index

    @property
    def Index(self)->int:
        return self._index

    @property
    def IsShortName(self) -> bool:
        return self._nameIndices[0] != 0

    @property
    def NameIndex(self) -> int:
        return self._nameIndices[1]

    @property
    def Name(self) -> str:
        try:
            if not self.IsShortName:
                return self._filehdr.stringtable.get_string_from_offset(self.NameIndex)
            else:
                return self.ShortName
        except:
            return "(n/a)"

    @Name.setter
    def Name(self, name: str):
        if len(name) > 8:
            self._filehdr.stringtable.set_string_at_offset(name, self.NameIndex)
        else:
            self.ShortName = name if len(name) == 8 else name + "\0"

    @property
    def BaseType(self) -> SymbolBaseType:
        return SymbolBaseType(self._type & 0xff)

    @property
    def TargetType(self) -> SymbolTargetType:
        return SymbolTargetType((self._type & 0xff00) >> 8)

    @property
    def IsFunction(self) -> bool:
        return self._type == 0x20

    @property
    def IsNotAFunction(self) -> bool:
        return self._type == 0

    @property
    def StorageClass(self) -> StorageClassType:
        return StorageClassType(self._storageClass)

    @StorageClass.setter
    def StorageClass(self, scl: StorageClassType):
        self._storageClass = scl.value

    def __repr__(self) -> str:
        return f"[Symbol#{self._index}@{hex(self.offset)}] {self.Name} value {hex(self.Value)}"

    def __str__(self) -> str:
        return self.__repr__()


class coff_sym_aux_secdef(Struct):
    _layout: StructLayout = StructLayout.Fixed
    _size = 18

    Length: int = Primitive(uint32_t, offset=0)
    NumberOfRelocations: int = Primitive(uint16_t, offset=4)
    NumberOfLinenumbers: int = Primitive(uint16_t, offset=6)
    CheckSum: int = Primitive(uint32_t, offset=8)
    Number: int = Primitive(uint16_t, offset=12)
    Selection: int = Primitive(uint8_t, offset=14)


class coff_strings(Struct):
    _layout: StructLayout = StructLayout.Sequential

    Size: int = Primitive(uint32_t)

    def __init__(self, filehdr: coff_file_header, mem: IMemory, offset: int) -> None:
        super().__init__(mem, offset)
        self._filehdr = filehdr

    @property
    def strings(self) -> Sequence[str]:
        data = self.mem.read(self.offset + uint32_t.get_size(),
                             self.Size - uint32_t.get_size())
        return [bts.decode("ascii") for bts in data.split(b'\0') if len(bts) > 0]

    @dataclass
    class StringRef:
        string: str
        offset: int

    def get_strings(self) -> List['StringRef']:
        refs = []
        idx = 4

        data:bytes = self.mem.read(self.offset, self.Size)

        while True:
            _idx = data.find(b'\0', idx)
            if _idx == -1: # No further terminator found
                break
        
            refs.append(coff_strings.StringRef(data[idx:_idx].decode("ascii"), idx))

            if _idx == len(data)-1:# Terminator was last char
                break

            idx = _idx + 1

        return refs

    def get_string_from_offset(self, offset: int):
        data = self.mem.read(self.offset + offset, self.Size - offset)
        idx = data.index(b'\0')
        return data[:idx].decode("ascii")

    def set_string_at_offset(self, string: str, offset: int):
        _mem : BufferMemory = self.mem
        
        # Retrieve current string
        data = self.mem.read(self.offset + offset, self.Size - offset)
        oldstr = data[:data.find(b'\0')]
        # Calculate delta
        delta = len(string) - len(oldstr)
        # Replace bytes (moving following indices)
        _mem.replace(self.offset + offset, self.offset + offset + len(oldstr), string.encode("ascii"))
        # Update own size
        self.Size = self.Size + delta
        # Relocate references to following indices
        self._filehdr.update_string_refs(offset + len(oldstr), delta)

    def append_string(self, string: str) -> int:
        _mem : BufferMemory = self.mem
        
        idx = self.Size
        _data = string.encode("ascii") + b'\0'
        # Append string at the end
        _mem.append(self.offset + self.Size, _data)
        # increment size by number of appended bytes
        self.Size = self.Size + len(_data)
        # return index of newly created string
        return idx
