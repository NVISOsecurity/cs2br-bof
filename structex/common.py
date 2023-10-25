from abc import ABC
from typing import Any

class IllegalOperationError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class PureVirtualCallError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class ISerializable(ABC):
    @classmethod
    def serialize(cls, thing: Any) -> bytes:
        raise PureVirtualCallError
        
    @classmethod
    def deserialize(cls, data: bytes) -> Any:
        raise PureVirtualCallError

    @classmethod
    def get_size(cls) -> int:
        raise PureVirtualCallError

class IMemory(ABC):
    def read(self, address: int, count: int) -> bytes:
        raise PureVirtualCallError
        
    def write(self, address: int, data: bytes) -> None:
        raise PureVirtualCallError

class IMemObject(ABC):
    def __init__(self, mem: IMemory, offset: int) -> None:
        self._offset = offset
        self._mem = mem

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def mem(self) -> IMemory:
        return self._mem