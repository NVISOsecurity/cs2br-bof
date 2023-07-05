#!/usr/bin/python3

import re
import os
import sys
import glob
import logging
import argparse
from typing import List

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)

PATTERN = re.compile(r"\s+(go)\(([^,]+?),([^\)]+?)\)\s*\{", re.MULTILINE)
PTCH_DIR = os.path.dirname(os.path.realpath(__file__))
STUB_PATH = os.path.join(PTCH_DIR, "badger_stub.c")
WRAP_PATH = os.path.join(PTCH_DIR, "beacon_wrapper.h")
PTCH_COMMENT = "// Patched by cs2br-bof-patch"

# Steps:
# 1. Identify beacon.h
# 2. Replace beacon.h with beacon_wrapper.h
# 3. Identify entry file w/ go function
# 4. Append badger_stub.h to entry file
# 6. Done?

# Also write customized beacon_generate.py


def check_patch(file: str, forcepatch: bool) -> bool:
    with open(file, "r") as f:
        state = f.readline().startswith(PTCH_COMMENT)

    if state:
        if not forcepatch:
            logging.info(f'Skipping "{file}"; already patched!')
            return False
        logging.info(f'Re-patching "{file}"...')
    else:
        logging.info(f'Patching "{file}"...')

    return True

def is_entrypoint(entryc: str) -> bool:
    with open(entryc, "r") as f:
        res = next(re.finditer(PATTERN, f.read()), None)
        return res is not None


def check_files():
    if not os.path.exists(STUB_PATH):
        raise FileNotFoundError(f'Missing patch file: "{STUB_PATH}"')
    if not os.path.exists(WRAP_PATH):
        raise FileNotFoundError(f'Missing patch file: "{WRAP_PATH}"')


def find_files(name: str, dir: str) -> List[str]:
    # Supplied absolute file path?
    if os.path.isabs(name):
        if not os.path.exists(name):
            raise FileNotFoundError(f'Specified file "{name}" not found.')
        return [name]

    # Supplied relative file path?
    if os.path.exists(name):
        return [os.path.abspath(name)]

    # Search for pattern/name
    files = glob.glob(os.path.join(dir, "**", name), recursive=True)
    if not files:
        raise FileNotFoundError(
            f'Could not find any file with the specified name/pattern "{name}" in "{dir}"!')
    
    return [os.path.abspath(file) for file in files]

def patch_header(beaconh: str, forcepatch: bool = False, dry: bool = False) -> bool:
    if not check_patch(beaconh, forcepatch): return False
    if dry: return True

    with open(WRAP_PATH, "r") as infile:
        with open(beaconh, "w") as outfile:
            outfile.write(PTCH_COMMENT + "\n")
            outfile.write(infile.read())

    return True


def patch_entryc(entryc: str, forcepatch: bool = False, dry: bool = False) -> bool:
    if not check_patch(entryc, forcepatch): return False
    if dry: return True

    # TODO: Test if entrypoint rename is actually needed.
    # Find & rename "go" entrypoint
    with open(entryc, "r") as outfile:
        contents = outfile.read()

    contents = re.sub(PATTERN, r" csentry(\2, \3) {", contents)

    # Append custom stub 
    contents += "\n\n"
    with open(STUB_PATH, "r") as outfile:
        contents += outfile.read()

    # Write back file
    with open(entryc, "w") as outfile:
        outfile.write(PTCH_COMMENT + "\n")
        outfile.write(contents)

    return True

def main():
    print(r"""
  ____________  ___  ___    ___  ____  ____  ___  ___ _____________ _________ 
 / ___/ __/_  |/ _ )/ _ \  / _ )/ __ \/ __/ / _ \/ _ /_  __/ ___/ // / __/ _ \
/ /___\ \/ __// _  / , _/ / _  / /_/ / _/  / ___/ __ |/ / / /__/ _  / _// , _/
\___/___/____/____/_/|_| /____/\____/_/   /_/  /_/ |_/_/  \___/_//_/___/_/|_| 
    by NVISO
""")
    try:
        # Ensure we can run in the first place
        check_files()

        # Parsing args
        parser = argparse.ArgumentParser(
            "patch", description="Patches Cobalt Strike BOF source code to be compatible with BruteRatel")
        parser.add_argument("--src", default=os.path.curdir,
                            help=f'Directory of source code to patch (default: current working dir, currently "{os.path.abspath(os.path.curdir)}")')
        parser.add_argument("--beaconh", default="beacon.h",
                            help='Name/pattern of or path to the headerfile(s) with Cobalt Strike beacon definitions to patch (default: "beacon.h")')
        parser.add_argument("--entrypoint", default="*.c",
                            help='Name or pattern of the source file(s) that contain(s) the Cobalt Strike "go" entrypoint (default: "*.c", so any C source file).')
        parser.add_argument("--forcepatch", default=False, action="store_true", help="Force patching already patched files")
        parser.add_argument("--dry", action="store_true", default=False, help="Dry-run: don't actually patch any files but show which actions will be executed.")

        args = parser.parse_args(sys.argv[1:])

        headers = find_files(args.beaconh, args.src)
        entries = find_files(args.entrypoint, args.src)
        entries = [e for e in entries if is_entrypoint(e)]

        if not entries: raise ValueError(f'None of the source files found with name/pattern "{args.entrypoint}" in directory "{args.src}" contain a CS entrypoint!')

        logging.info(f"Identified {len(headers)} header file(s), {len(entries)} source file(s) to patch.")

        logging.info("Patching header files:")
        num_patches = sum(1 if patch_header(header, args.forcepatch, args.dry) else 0 for header in headers)
        logging.info(f"Patched {num_patches} header file(s)!")

        logging.info("Patching entrypoint source files:")
        num_patches = sum(1 if patch_entryc(entryc, args.forcepatch, args.dry) else 0 for entryc in entries)
        logging.info(f"Patched {num_patches} entrypoint source file(s)!")
        

    except Exception as e:
        logging.error("cs2br-bof-patch broke, here's details:", exc_info=e)


if __name__ == '__main__':
    main()