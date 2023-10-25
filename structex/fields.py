from abc import ABC
import struct
from typing import Any, Generic, Type, TypeVar

from .basetypes import IField, Struct, uint32_t, uint64_t
from .common import IMemory, ISerializable, IMemObject, IllegalOperationError


W = TypeVar('W', Struct, ISerializable)
V = TypeVar('V', bound=ISerializable)

class Primitive(Generic[V], IField):
    def __init__(self, cls: Type[V], offset: int = None) -> None:
        super().__init__(offset)
        self._cls = cls

    @property
    def cls(self) -> Type[V]:
        return self._cls

    def get_value(self, mem: IMemory, address: int) -> Any:        
        data = mem.read(address, self.cls.get_size())
        return self.cls.deserialize(data)

    def set_value(self, mem: IMemory, address: int, value: Any) -> None:
        data = self.cls.serialize(value)
        mem.write(address, data)

    def get_size(self) -> int:
        return self.cls.get_size()

K = TypeVar('K', bound=Struct)

class Instance(Generic[K], IField):
    def __init__(self, cls: Type[K], offset: int = None) -> None:
        super().__init__(offset)
        self._cls = cls

    @property
    def cls(self) -> Type[K]:
        return self._cls

    def get_value(self, mem: IMemory, address: int) -> Any:        
        return self.cls(mem, address)

    def get_size(self) -> int:
        return self.cls.get_size()

class Array(Generic[W], IField):
    def __init__(self, cls: Type[W], count: int, offset: int = None, element_size: int = None) -> None:
        super().__init__(offset)
        self._cls = cls
        self._count = count
        self._element_size = element_size if element_size else cls.get_size()

    @property
    def cls(self) -> Type[V]:
        return self._cls
    
    @property
    def count(self) -> int:
        return self._count
    
    @property
    def element_size(self) -> int:
        return self._element_size

    def get_size(self) -> int:
        return self.count * self.element_size
    
    class ArraySequence(Generic[W], IMemObject):
        def __init__(self, mem: IMemory, offset: int, cls: Type[W], count: int, element_size: int) -> None:
            super().__init__(mem, offset)
            self._cls = cls
            self._count = count
            self._element_size = element_size

        def __len__(self) -> int:
            return self._count

        def _get_element_address(self, idx: int) -> int:
            return self.offset + idx * self._element_size

        def __getitem__(self, key: int) -> W:
            if issubclass(self._cls, Struct):
                return self._cls(self.mem, self._get_element_address(key))
            elif issubclass(self._cls, ISerializable):
                data = self.mem.read(self._get_element_address(key), self._cls.get_size())
                return self._cls.deserialize(data)
            else:
                raise IllegalOperationError("Can't perform __getitem__ for a key that's neither a Struct nor an ISerializable!")

        def __setitem__(self, key: int, value: W) -> None:
            if not issubclass(self._cls, ISerializable):
                raise IllegalOperationError("Can't perform __setitem__ for a key that's not an ISerializable!")
            data = self._cls.serialize(value)
            self.mem.write(self._get_element_address(key), data)

    def get_value(self, mem: IMemory, address: int) -> Any:
        return Array.ArraySequence(mem, address, self.cls, self.count, self.element_size)

class FixedString(IField):
    def __init__(self, byte_length: int, offset: int = None, encoding = "ascii", add_null_terminator: bool = False) -> None:
        super().__init__(offset)
        self._byte_length = byte_length
        self._encoding = encoding
        self._add_null_terminator = add_null_terminator

    def get_value(self, mem: IMemory, address: int) -> Any:
        data = mem.read(address, self._byte_length)
        return data.decode(self._encoding).split('\0')[0]

    def set_value(self, mem: IMemory, address: int, value: str) -> None:
        if self._add_null_terminator: value += '\0'
        data = value.encode(self._encoding)
        if len(data) > self._byte_length:
            raise IllegalOperationError(f"Supplied string is too long for this FixedString: {len(data)} > {self._byte_length}")
        mem.write(address, data)

    def get_size(self) -> int:
        return self._byte_length

class Pointer(Generic[W], IField):
    PTR_TYPE: ISerializable = uint32_t if struct.calcsize("P") == 4 else uint64_t

    def __init__(self, cls: Type[W], offset: int = None) -> None:
        super().__init__(offset)
        self._cls = cls

    @property
    def cls(self) -> Type[V]:
        return self._cls

    def _get_address(self, mem:IMemory, address: int) -> int:
        addr_data = mem.read(address + self.offset, Pointer.PTR_TYPE.get_size())
        return Pointer.PTR_TYPE.deserialize(addr_data)

    def get_value(self, mem: IMemory, address: int) -> Any:
        addr = self._get_address(mem, address)
        if issubclass(self._cls, Struct):
            return self._cls(self.mem, addr)
        elif issubclass(self._cls, ISerializable):
            data = self.mem.read(addr, self._cls.get_size())
            return self._cls.deserialize(data)
        else:
            raise IllegalOperationError("Can't dereference a pointer that's neither of type Struct nor ISerializable!")

    def set_value(self, mem: IMemory, address: int, value: Any) -> None:
        if not issubclass(self._cls, ISerializable):
            raise IllegalOperationError("Can't perform set_value for a reference that's not an ISerializable!")

        addr = self._get_address(mem, address)
        data = self._cls.serialize(value)
        self.mem.write(addr, data)

    def get_size(self) -> int:
        return Pointer.PTR_TYPE.get_size()