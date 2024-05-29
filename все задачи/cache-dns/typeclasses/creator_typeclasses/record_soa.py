import struct

from utils.utils_dns_packet_creator import convert_name_to_bits
from exceptions.creator_exception import CreatorException

SERIAL_NUMBER_OFFSET = 32
REFRESH_INTERVAL_OFFSET = 32
RETRY_INTERVAL_OFFSET = 32
EXPIRE_LIMIT_OFFSET = 32
MINIMUM_TTL_OFFSET = 32


class RecordTypeSoa:
    # Здесь в bits_stream передается полный пакет, поскольку может встретиться коротокая ссылка
    def __init__(self, primary_server, responsible_authoritative, serial_number, refresh_interval, retry_interval, expire_limit, minimum_ttl):
        self.primary_server = primary_server
        self.responsible_authority = responsible_authoritative

        self.serial_number = serial_number
        self.refresh_interval = refresh_interval
        self.retry_interval = retry_interval
        self.expire_limit = expire_limit
        self.minimum_ttl = minimum_ttl

    def to_bin(self, names_minder: dict, start_soa_seek: int) -> tuple[bytes, int]:
        if self.minimum_ttl and self.expire_limit and self.serial_number and self.refresh_interval \
                and self.retry_interval:
            server = convert_name_to_bits(self.primary_server, names_minder, start_soa_seek)
            bits_primary_server = server[0]
            start_soa_seek += server[1]

            authority_encoded = convert_name_to_bits(self.responsible_authority, names_minder, start_soa_seek)

            bits_responsible_authority = authority_encoded[0]

            start_soa_seek += authority_encoded[1]

            bits_options = struct.pack('!IIIII', self.serial_number, self.refresh_interval, self.retry_interval, self.expire_limit, self.minimum_ttl)

            return bits_primary_server + bits_responsible_authority + bits_options, start_soa_seek + 160

        raise CreatorException(f'Плохой soa:{self.retry_interval}, {self.refresh_interval},'
                               f'{self.primary_server}, {self.expire_limit}, {self.minimum_ttl}, '
                               f'{self.responsible_authority}, {self.refresh_interval}')
