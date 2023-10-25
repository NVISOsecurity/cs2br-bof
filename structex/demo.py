from typing import Sequence
from structex.basetypes import Struct, StructLayout, int32_t, uint16_t, uint32_t, uint64_t, uint8_t
from structex.common import IMemory
from structex.fields import Array, FixedString, Instance, Primitive
from structex.memory import BufferMemory, CachedMemory

class IMAGE_DOS_HEADER(Struct):
    _layout: StructLayout = StructLayout.Sequential

    e_magic: str = FixedString(2) # Magic number
    e_cblp: int = Primitive(uint16_t) # Bytes on last page of file
    e_cp: int = Primitive(uint16_t) # Pages in file
    e_crlc: int = Primitive(uint16_t) # Relocations
    e_cparhdr: int = Primitive(uint16_t) # Size of header in paragraphs
    e_minalloc: int = Primitive(uint16_t) # Minimum extra paragraphs needed
    e_maxalloc: int = Primitive(uint16_t) # Maximum extra paragraphs needed
    e_ss: int = Primitive(uint16_t) # Initial (relative) SS value
    e_sp: int = Primitive(uint16_t) # Initial SP value
    e_csum: int = Primitive(uint16_t) # Checksum
    e_ip: int = Primitive(uint16_t) # Initial IP value
    e_cs: int = Primitive(uint16_t) # Initial (relative) CS value
    e_lfarlc: int = Primitive(uint16_t) # File address of relocation table
    e_ovno: int = Primitive(uint16_t) # Overlay number
    e_res_0: int = Primitive(uint16_t) # reserved words
    e_res_1: int = Primitive(uint16_t) # reserved words
    e_res_2: int = Primitive(uint16_t) # reserved words
    e_res_3: int = Primitive(uint16_t) # reserved words
    e_oemid: int = Primitive(uint16_t) # OEM identifier (for e_oeminfo)
    e_oeminfo: int = Primitive(uint16_t) # OEM information; e_oemid specific
    e_res2_0: int = Primitive(uint16_t) # reserved words
    e_res2_1: int = Primitive(uint16_t) # reserved words
    e_res2_2: int = Primitive(uint16_t) # reserved words
    e_res2_3: int = Primitive(uint16_t) # reserved words
    e_res2_4: int = Primitive(uint16_t) # reserved words
    e_res2_5: int = Primitive(uint16_t) # reserved words
    e_res2_6: int = Primitive(uint16_t) # reserved words
    e_res2_7: int = Primitive(uint16_t) # reserved words
    e_res2_8: int = Primitive(uint16_t) # reserved words
    e_res2_9: int = Primitive(uint16_t) # reserved words
    e_lfanew: int = Primitive(uint32_t) 

class IMAGE_FILE_HEADER(Struct):
    _layout: StructLayout = StructLayout.Sequential

    Magic: str = FixedString(4) 
    Machine: int = Primitive(uint16_t) 
    NumberOfSections: int = Primitive(uint16_t) 
    TimeDateStamp: int = Primitive(uint32_t) 
    PointerToSymbolTable: int = Primitive(uint32_t) 
    NumberOfSymbols: int = Primitive(uint32_t) 
    SizeOfOptionalHeader: int = Primitive(uint16_t) 
    Characteristics: int = Primitive(uint16_t) 

class IMAGE_OPTIONAL_HEADER64(Struct):
    _layout: StructLayout = StructLayout.Sequential

    Magic: int = Primitive(uint16_t) 
    MajorLinkerVersion: int = Primitive(uint8_t) 
    MinorLinkerVersion: int = Primitive(uint8_t) 
    SizeOfCode: int = Primitive(int32_t) 
    SizeOfInitializedData: int = Primitive(int32_t) 
    SizeOfUninitializedData: int = Primitive(int32_t) 
    AddressOfEntryPoint: int = Primitive(int32_t) 
    BaseOfCode: int = Primitive(int32_t) 
    ImageBase: int = Primitive(uint64_t) 
    SectionAlignment: int = Primitive(int32_t) 
    FileAlignment: int = Primitive(int32_t) 
    MajorOperatingSystemVersion: int = Primitive(uint16_t) 
    MinorOperatingSystemVersion: int = Primitive(uint16_t) 
    MajorImageVersion: int = Primitive(uint16_t) 
    MinorImageVersion: int = Primitive(uint16_t) 
    MajorSubsystemVersion: int = Primitive(uint16_t) 
    MinorSubsystemVersion: int = Primitive(uint16_t) 
    Win32VersionValue: int = Primitive(int32_t) 
    SizeOfImage: int = Primitive(int32_t) 
    SizeOfHeaders: int = Primitive(int32_t) 
    CheckSum: int = Primitive(int32_t) 
    Subsystem: int = Primitive(uint16_t) 
    DllCharacteristics: int = Primitive(uint16_t) 
    SizeOfStackReserve: int = Primitive(uint64_t) 
    SizeOfStackCommit: int = Primitive(uint64_t) 
    SizeOfHeapReserve: int = Primitive(uint64_t) 
    SizeOfHeapCommit: int = Primitive(uint64_t) 
    LoaderFlags: int = Primitive(int32_t) 
    NumberOfRvaAndSizes: int = Primitive(int32_t) 

class IMAGE_SECTION_HEADER(Struct):
    _layout: StructLayout = StructLayout.Sequential

    Name: str = FixedString(8)
    VirtualSize: int = Primitive(uint32_t) 
    VirtualAddress: int = Primitive(uint32_t) 
    SizeOfRawData: int = Primitive(uint32_t) 
    PointerToRawData: int = Primitive(uint32_t) 
    PointerToRelocations: int = Primitive(uint32_t) 
    PointerToLinenumbers: int = Primitive(uint32_t) 
    NumberOfRelocations: int = Primitive(uint16_t) 
    NumberOfLinenumbers: int = Primitive(uint16_t) 
    Characteristics: int = Primitive(uint32_t)

    def __str__(self) -> str:
        return self.Name

    def __repr__(self) -> str:
        return self.Name

with open("C:\\Windows\\System32\\notepad.exe", "rb") as file:
    DATA = file.read(-1)

mem_base = BufferMemory(DATA)
mem = CachedMemory(mem_base, 10)

pos = 0
img_dos = IMAGE_DOS_HEADER(mem, pos)
pos = img_dos.e_lfanew
img_file = IMAGE_FILE_HEADER(mem, pos)
pos += img_file.get_size()
img_opt = IMAGE_OPTIONAL_HEADER64(mem, pos)
pos += img_opt.get_size() + 128

sections = [
    IMAGE_SECTION_HEADER(mem, pos + IMAGE_SECTION_HEADER.get_size() * i) for i in range(img_file.NumberOfSections)
]

print(img_dos)
print()