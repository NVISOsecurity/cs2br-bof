#!/usr/bin/python3

from struct import pack, calcsize
import base64
import cmd
import zlib
import os

class BeaconPack:
    def __init__(self):
        self._buffer = b''
        self._size = 0 #TODO: Just use len(buffer) instead?

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

if __name__ == "__main__":
    print(r"""
  ____________  ___  ___    ___  ____  ____  ___   ___  _________  __________  _________  ___ __________  ___ 
 / ___/ __/_  |/ _ )/ _ \  / _ )/ __ \/ __/ / _ | / _ \/ ___/ __/ / ___/ __/ |/ / __/ _ \/ _ /_  __/ __ \/ _ \
/ /___\ \/ __// _  / , _/ / _  / /_/ / _/  / __ |/ , _/ (_ /\ \  / (_ / _//    / _// , _/ __ |/ / / /_/ / , _/
\___/___/____/____/_/|_| /____/\____/_/   /_/ |_/_/|_|\___/___/  \___/___/_/|_/___/_/|_/_/ |_/_/  \____/_/|_| 
    by NVISO, based on https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py
""")
    cmdloop = MainLoop()
    cmdloop.do_help("")
    cmdloop.cmdloop()