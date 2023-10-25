#!/usr/bin/python3

from struct import pack, calcsize
import base64
import cmd
from typing import List, Tuple
import zlib
import sys
import os


class BeaconPack:
    def __init__(self):
        self._buffer = b''
        self._size = 0  # TODO: Just use len(buffer) instead?

    @property
    def buffer(self):
        return self._buffer

    def addshort(self, short):
        self._buffer += pack("<h", short)
        self._size += 2

    def addint(self, dint):
        self._buffer += pack("<i", dint)
        self._size += 4

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self._buffer += pack(fmt, len(s)+1, s)
        self._size += calcsize(fmt)

    def addWstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-16_le")
        fmt = "<L{}s".format(len(s) + 2)
        self._buffer += pack(fmt, len(s)+2, s)
        self._size += calcsize(fmt)

    def addFile(self, s):
        with open(s, "rb") as f:
            data = f.read(-1)
        fmt = "<L{}s".format(len(data))
        self._buffer += pack(fmt, len(data), data)
        self._size += calcsize(fmt)



class MainLoop(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.BeaconPack = BeaconPack()
        self.intro = "BOF parameter encoder"
        self.prompt = "CMD> "

    def do_addWString(self, text):
        '''addWString String here
        Append the wide string to the text.
        '''
        self.BeaconPack.addWstr(text)

    def do_addString(self, text):
        '''addString string here
        Append the utf-8 string here.
        '''
        self.BeaconPack.addstr(text)

    @staticmethod
    def _b64print(buffer):
        bts = base64.b64encode(buffer).decode("ascii")
        print(f"Argument buffer: {len(buffer)} bytes")
        print(f"Base64 encoded: {len(bts)} chars")
        print(bts)

    # TODO: Only keep generate, auto-compress if more efficient, make compression optional
    def do_generate(self, text):
        '''generate
        Generate the buffer for the BOF arguments
        '''
        MainLoop._b64print(self.BeaconPack.buffer)

    def do_compress(self, text):
        '''compress
        Generate the buffer for the BOF arguments (gzip compressed)'''
        buff = self.BeaconPack.buffer
        print(len(buff))
        bts = b'GZ' + pack("<i", len(buff)) + zlib.compress(buff)
        MainLoop._b64print(bts)

    def do_addInt(self, text):
        '''addInt integer
        Add an int32_t to the buffer
        '''
        try:
            converted = int(text)
            self.BeaconPack.addint(converted)
        except:
            print("Failed to convert to int\n")

    def do_addShort(self, text):
        '''addShort integer
        Add an uint16_t to the buffer
        '''
        try:
            converted = int(text)
            self.BeaconPack.addshort(converted)
        except:
            print("Failed to convert to short\n")

    def do_addFile(self, text):
        '''addFile path
        Add a file as binary data to the buffer
        '''
        try:
            self.BeaconPack.addFile(text)
        except Exception as e:
            print(e.args)
            print("Failed to add file to buffer\n")

    def do_show(self, text):
        '''show
        Prints a hexdump of the current buffer'''
        buff = self.BeaconPack.buffer
        
        def toascii(byte: int):
            if byte <= 0 or byte >= 128:
                return "." 
            _str = bytes([byte]).decode("ascii")
            if not _str.isprintable() or _str.isspace():
                return "."
            
            return _str

        width = 32
        for line, block in enumerate(buff[i: i+width] for i in range(0, len(buff), width)):
            _hex =   ' '.join([hex(b)[2:].rjust(2, '0') for b in block] + ["  " for _ in range(width - len(block))])
            _ascii = ''.join([toascii(b) for b in block] + [' ' for _ in range(width - len(block))])
            print("@{} | {} | {}".format(
                hex(line*width)[2:].rjust(8, '0'),
                _hex,
                _ascii))

    def do_reset(self, text):
        '''reset
        Reset the buffer here.
        '''
        self.BeaconPack._buffer = b''
        self.BeaconPack._size = 0

    def do_exit(self, text):
        '''exit
        Exit the console
        '''
        return True


def process_args(args: List[str]) -> Tuple[bool, str]:
    pack = BeaconPack()

    def tryaction(fn, errortext) -> bool:
        try:
            fn()
            return True
        except Exception as e:
            print(errortext + ": " + str(e.args))
            return False

    def process_arg(index:int, arg:str) -> bool:
        prefix = arg[0]
        value = arg[2:]

        if not prefix in ["b","i","s","z","Z","f"]:
            print(f'Argument #{index+1}: Invalid argument type "{prefix}"')
            return False

        if len(value) == 0 and not prefix in ["z", "Z"]:
            print(f"Argument #{index+1}: Empty value not allowed for prefix {prefix}")
            return False

        if  (prefix == "b" and not tryaction(lambda: pack.addstr(base64.b64decode(value).decode()), f"Argument #{index+1}: Failed to base64 decode binary data")) or \
            (prefix == "i" and not tryaction(lambda: pack.addint(int(value)), f"Argument #{index+1}: Failed to convert arg to int")) or \
            (prefix == "s" and not tryaction(lambda: pack.addshort(int(value)), f"Argument #{index+1}: Failed to convert arg to short")) or \
            (prefix == "z" and not tryaction(lambda: pack.addstr(value), f"Argument #{index+1}: Failed to add string")) or \
            (prefix == "Z" and not tryaction(lambda: pack.addWstr(value), f"Argument #{index+1}: Failed to add string")) or \
            (prefix == "f" and not tryaction(lambda: pack.addFile(value), f"Argument #{index+1}: Failed to add file")):
            return False
        
        return True
    
    for i, arg in enumerate(args):
        if not process_arg(i, arg):
            return [False, ""]
        
    return [True, base64.b64encode(pack.buffer).decode("ascii")]


if __name__ == "__main__":
    print(r"""
  ____________  ___  ___    ___  ____  ____  ___   ___  _________  __________  _________  ___ __________  ___ 
 / ___/ __/_  |/ _ )/ _ \  / _ )/ __ \/ __/ / _ | / _ \/ ___/ __/ / ___/ __/ |/ / __/ _ \/ _ /_  __/ __ \/ _ \
/ /___\ \/ __// _  / , _/ / _  / /_/ / _/  / __ |/ , _/ (_ /\ \  / (_ / _//    / _// , _/ __ |/ / / /_/ / , _/
\___/___/____/____/_/|_| /____/\____/_/   /_/ |_/_/|_|\___/___/  \___/___/_/|_/___/_/|_/_/ |_/_/  \____/_/|_| 
    by NVISO, based on https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py
""")
    _args = sys.argv[1:]
    if _args:
        res, txt = process_args(_args)
        if res: print(txt)
    else:
        cmdloop = MainLoop()
        cmdloop.do_help("")
        cmdloop.cmdloop()
