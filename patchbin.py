import argparse
import os
import subprocess
import sys
import logging
import struct
from typing import List, Tuple

from structex.memory import BufferMemory

from objfile import RelocType64, SectionDefintion, StorageClassType, coff_file_header, coff_sym

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)


# Logic


def run_command(prg, arguments: List[str], error_text: str = None) -> Tuple[int, str, str]:
    cmd = " ".join([prg] + list(arguments))
    logging.info(f'Executing "{cmd}"')
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, shell=True)
    stdout, stderr = proc.communicate()
    proc.wait()

    if proc.returncode != 0 and error_text is not None:
        raise Exception(f"{error_text}: {stderr} (code {proc.returncode})")

    return (proc.returncode, stdout.decode("utf-8"), stderr.decode("utf-8"))


CS_IMPORTS = ["BeaconCleanupProcess", "BeaconDataExtract", "BeaconDataInt", "BeaconDataLength", "BeaconDataParse", "BeaconDataShort", "BeaconFormatAlloc", "BeaconFormatAppend", "BeaconFormatFree", "BeaconFormatInt", "BeaconFormatPrintf",
              "BeaconFormatReset", "BeaconFormatToString", "BeaconGetSpawnTo", "BeaconInjectProcess", "BeaconInjectTemporaryProcess", "BeaconIsAdmin", "BeaconOutput", "BeaconPrintf", "BeaconRevertToken", "BeaconUseToken", "toWideChar"]

CS_DEF_IMPORTS = ["LoadLibraryA", "LoadLibraryW", "GetProcAddress",
                  "FreeLibrary", "GetModuleHandleA", "GetModuleHandleW"]


def check_cs2br(cs2br: coff_file_header):
    logging.info("Validating cs2br object file...")
    # TODO: Perform sanity checks:
    #   - contains all CS API implementations
    #   - contains default CS WinAPI imports
    #   - contains coffee entrypoint
    #   - contains no unresolved/unresolvable imports
    pass


def check_srcbof(bof: coff_file_header):
    logging.info("Validating source BOF object file...")
    # TODO: Perform sanity checks:
    #   - contains go entrypoint
    #   - contains no unresolved/unresolvable imports
    pass


def inject(fcs2br: str, fsrcbof: str, fdestbof: str):
    # Parse & validate input file
    ocs2br = coff_file_header(BufferMemory.from_file(fcs2br), 0)
    check_cs2br(ocs2br)

    osrcmem = BufferMemory.from_file(fsrcbof)
    osrcbof = coff_file_header(osrcmem, 0)
    check_srcbof(osrcbof)

    if os.path.exists(fdestbof):
        with open(fdestbof, "rb") as f:
            odestbof = coff_file_header(BufferMemory(f.read()), 0)

    # Only mix matching files
    if ocs2br.Machine != osrcbof.Machine:
        raise ValueError(
            "Compatibility layer and BOF were compiled for different platforms!")

    # Rewire CS API imports to CS2BR implementations: relocations + symbols!
    cs_patches = [imp for imp in CS_IMPORTS if any(
        filter(lambda s: s.Name == f"__imp_{imp}", osrcbof.symbols))]
    if cs_patches:
        logging.info(
            f"Found {len(cs_patches)} CS API import(s) that need(s) patching...")

        for symbol_name in cs_patches:
            logging.info(f"Reconfiguring __imp_{symbol_name}...")
            # In src BOF: set symbol's fields:
            # - Value: 0
            # - SectionNumber: 0 ("indicates that a reference to an external symbol is defined elsewhere")
            # - StorageClass: IMAGE_SYM_CLASS_EXTERNAL
            # - Rename: remove "__imp_" prefix
            # - _type: 32
            symbol = osrcbof.get_symbol_by_name(f"__imp_{symbol_name}")
            symbol.Value = 0
            symbol.SectionNumber = 0
            symbol.StorageClass = StorageClassType.IMAGE_SYM_CLASS_EXTERNAL
            #symbol.Name = symbol_name
            symbol.Name = f"__cs2br_{symbol_name}"
            symbol._type = 0

        fsrcbof = f"{fsrcbof}.tmp" # replace with python's temporary file?
        osrcmem.to_file(fsrcbof)
    else:
        logging.info("No CS APIs need patching!")

    cs_def_patches = [imp for imp in CS_DEF_IMPORTS if any(
        s for s in osrcbof.symbols if s.Name == f'__imp_{imp}')]
    if cs_def_patches:
        logging.info(
            f"Found {len(cs_def_patches)} Win32 API import(s) that need(s) patching...")
        for imp in cs_def_patches:
            for sym in (s for s in osrcbof.symbols if s.Name == f'__imp_{imp}'):
                logging.info(
                    f"Renaming symbol __imp_{imp} => __imp_KERNEL32${imp}...")
                sym.Name = f'__imp_KERNEL32${imp}'

        fsrcbof = f"{fsrcbof}.tmp" if not fsrcbof.endswith(".tmp") else fsrcbof
        with open(fsrcbof, "wb") as f:
            f.write(osrcmem.buffer)
    else:
        logging.info("No default Win32 APIs need patching!")

    # Merge files
    logging.info("Merging CS2BR compatibility layer into BOF...")
    run_command(
        "ld",
        ["--relocatable", fsrcbof, fcs2br, "-o",
            fdestbof, "--oformat", "pe-x86-64"],
        "Merging failed"
    )

    odestmem:BufferMemory = BufferMemory.from_file(fdestbof)
    odestbof = coff_file_header(odestmem, 0)

    # Rename go entrypoint
    ep = next(filter(lambda s: s.Name == "go", odestbof.symbols))
    ep.ShortName = "csentry"

    # Idea: identify relocs in data which
    #       - are addr64
    #       - point to .text
    #       - got the same offset as __cs2br_ methods
    # Then:
    #       - clear offset at reloc addr
    #       - rewire reloc to symbol in .text which has
    symbols_to_reset = set()
    txtsectionidx = next((i for i, v in enumerate(odestbof.sections) if v.Name == ".text"), -1) # TODO: Check for executable code flags instead of name
    txtsectionidx, txtsection = next(((i, s) for i, s in enumerate(odestbof.sections) if s.Name == ".text"), (-1,None))
    # TODO: check txtsection NONE
    txtsectionsymbol = next(s for s in odestbof.symbols if s.Name == txtsection.Name and s.Value == 0 and s.SectionNumber == txtsectionidx + 1)

    for section in odestbof.sections:
        for reloc in section.relocations:
            if reloc.Type64 != RelocType64.IMAGE_REL_AMD64_ADDR64:
                continue

            sold = reloc.SymbolTableEntry
            # Check that the current symbol points into the text section
            if sold.SectionNumber != txtsectionidx + 1:
                continue

            # Get the corresponding __cs2br_ symbol
            scs2br = next((s for s in odestbof.symbols if s.Name.startswith("__cs2br_") and reloc.VirtualAddress == s.Value), None)
            if scs2br is None:
                continue

            # Get the actual .text symbol
            snew = next((s for s in odestbof.symbols if s.Name == scs2br.Name[8:]))
            snew._type = 0
            
            reloc_offset = struct.unpack("<Q", odestmem.read(section.PointerToRawData + reloc.VirtualAddress, 8))[0]

            # Clear the current offset
            odestmem.write(section.PointerToRawData + reloc.VirtualAddress, struct.pack("<Q", 0))

            logging.info(f'Pointing relocation {section.Name}:{hex(reloc.VirtualAddress)} from {odestbof.sections[sold.SectionNumber-1].Name}:{hex(sold.Value)}+{hex(reloc_offset)} (=> {scs2br.Name}) to {txtsection.Name}:{hex(snew.Value)} (=> {snew.Name})...')

            # Point to the appropriate symbol
            reloc.SymbolTableIndex = txtsectionsymbol.Index

            # Write back offset
            odestmem.write(section.PointerToRawData + reloc.VirtualAddress, struct.pack("<Q", snew.Value))
            # Remember to reset the symbol's value to 0
            symbols_to_reset.add(reloc.SymbolTableIndex)

    # Write back changed dest BOF
    odestmem.to_file(fdestbof)

    logging.info(f'Stripping unneeded symbols from patched BOF...')
    run_command(
        "strip",
        ["--strip-unneeded","--keep-symbol='.text'", "--remove-section='.pdata'","--remove-section='.xdata'","--remove-section='.rdata$zzz'", fdestbof],
        "Failed to strip unneeded symbols")

    # Re-read destination BOF
    odestmem = odestmem.from_file(fdestbof)
    odestbof = coff_file_header(odestmem, 0)


    # Write back changed dest BOF
    odestmem.to_file(fdestbof)
    

    # Cleanup
    if fsrcbof.endswith(".tmp"):
        logging.info(f"Cleanup: removing temporary file {fsrcbof}")
        os.remove(fsrcbof)


def main():
    print(r"""
  ____________  ___  ___    ___  ____  ____  ___  _____  _____   _____  __  ___  ___ _____________ _________
 / ___/ __/_  |/ _ )/ _ \  / _ )/ __ \/ __/ / _ )/  _/ |/ / _ | / _ \ \/ / / _ \/ _ /_  __/ ___/ // / __/ _ \
/ /___\ \/ __// _  / , _/ / _  / /_/ / _/  / _  |/ //    / __ |/ , _/\  / / ___/ __ |/ / / /__/ _  / _// , _/
\___/___/____/____/_/|_| /____/\____/_/   /____/___/_/|_/_/ |_/_/|_| /_/ /_/  /_/ |_/_/  \___/_//_/___/_/|_|
    by NVISO
""")

    parser = argparse.ArgumentParser(
        "patchbin",
        description="Injects the CS2BR compatibility layer into a compiled BOF")
    parser.add_argument(
        "--cs2br",
        default="cs2br.o",
        help="Compiled CS2BR compatibility layer object file")
    parser.add_argument(
        "src",
        help="Source BOF to inject CS2BR into")
    parser.add_argument(
        "dst",
        help="Destination path to save the patched BOF to")

    args = parser.parse_args(sys.argv[1:])

    if not os.path.exists(args.cs2br):
        raise FileNotFoundError(
            "Specified CS2BR compatibility layer object file not found")

    if not os.path.exists(args.src):
        raise FileNotFoundError(
            "Specified source BOF not found")

    inject(args.cs2br, args.src, args.dst)


if __name__ == '__main__':
    main()
