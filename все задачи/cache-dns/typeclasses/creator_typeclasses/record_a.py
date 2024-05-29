import struct

from exceptions.creator_exception import CreatorException


class RecordTypeA:
    def __init__(self, ip_v4):
        self.ip_v4: str = ip_v4

    def to_bin(self, init_seek: int) -> tuple[bytes, int]:
        seek = init_seek + 32
        if self.ip_v4:
            ans = b''
            for byte in self.ip_v4.split('.'):
                ans += struct.pack('!B', int(byte))
            return ans, seek
        raise CreatorException(f'плохой адрес: {self.ip_v4}')
