from typing import Dict, List
from .common import IMemory


class BufferMemory(IMemory):
    def __init__(self, buffer: bytes) -> None:
        self._buffer = buffer

    @property
    def buffer(self) -> bytes:
        return self._buffer

    def read(self, address: int, count: int) -> bytes:
        return self._buffer[address: address + count]

    def write(self, address: int, data: bytes) -> None:
        temp = bytearray(self._buffer)
        temp[address: address + len(data)] = data
        self._buffer = bytes(temp)

    def insert(self, address: int, data: bytes) -> None:
        self.replace(self, address, address, data)

    def replace(self, addrfrom: int, addrto: int, data: bytes)->None:
        temp = bytearray(self._buffer)
        temp[addrfrom:addrto] = data
        self._buffer = bytes(temp)

    def append(self, data: bytes) -> None:
        self._buffer += data

    def to_file(self, path: str):
        with open(path, "wb") as f:
            f.write(self._buffer)

    def from_file(self, path: str) -> 'BufferMemory': 
        return BufferMemory.from_file(path)

    @staticmethod
    def from_file(path: str) -> 'BufferMemory':
        with open(path, "rb") as f:
            return BufferMemory(f.read())


class CachedMemory(IMemory):
    class Cache:
        def __init__(self, data: bytes) -> None:
            self.data: bytes = data
            self.written: bool = False

    def __init__(self, base_mem: IMemory, cache_size: int = 4096) -> None:
        super().__init__()
        self._base_mem = base_mem
        self._cache_size = cache_size
        self._caches: Dict[int, CachedMemory.Cache] = {}

    @staticmethod
    def get_affected_caches(addr_from: int, addr_to: int, cache_size: int) -> List[int]:
        _base = addr_from - (addr_from % cache_size)
        return [i for i in range(_base, addr_to + 1, cache_size)]

    def read(self, address: int, count: int) -> bytes:
        _caches = CachedMemory.get_affected_caches(
            address, address + count, self._cache_size)
        _cache_data = b''.join(self._read_cache(_cache) for _cache in _caches)
        return _cache_data[(address % self._cache_size):(address % self._cache_size) + count]

    def _read_cache(self, addr_cache: int) -> bytes:
        _cache = self._caches.get(addr_cache, None)
        if not _cache:
            _cache = CachedMemory.Cache(
                self._base_mem.read(addr_cache, self._cache_size))
            self._caches[addr_cache] = _cache
        return _cache.data

    def write(self, address: int, data: bytes) -> None:
        _cache_addrs = CachedMemory.get_affected_caches(
            address, address + len(data), self._cache_size)
        _caches = {addr: self._read_cache(addr) for addr in _cache_addrs}
        # Insert first cache:
