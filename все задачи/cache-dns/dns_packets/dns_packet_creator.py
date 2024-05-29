"""
Класс для формирования днс пакета
"""
import struct

from dns_packets.config_dns import DNSConfig
from exceptions.creator_exception import CreatorException
from utils.utils_dns_packet_creator import MAX_ID, BIN_OFFSET, QR_AA_TC_RD_RA_VALUES, OP_VALUES, OP_CODE_SIZE, MAX_Z, \
    Z_SIZE, \
    RCODE_VALUES, RCODE_SIZE, HEADER_SIZE, convert_name_to_bits, \
    MAPPER_INVERSE_TYPE_RECORD, MAPPER_INVERSE_CLASS_RECORD, answer_to_bits


class DNSCreator:
    def __init__(self, config: DNSConfig):
        self._config = config

    def to_bin(self):
        bytes_packet = b''  # Здесь все в бинарку сложим и отпарсим потом hex

        """
        Здесь нужно завести какой-то словарь для использования потом сжатых меток
        ключ - имя, значение - указатель, куда сместится от начала пакета
        """

        names_minder = self._config.names_minder

        if self._config.ID > MAX_ID:
            raise CreatorException(f"ID больше максимального допустимого id (65535): {self._config.ID}")

        id_bits: bytes = struct.pack('!H', self._config.ID)

        bytes_packet += id_bits

        if self._config.QR not in QR_AA_TC_RD_RA_VALUES:
            raise CreatorException(
                f'Поле не может быть однозначно идентифицировано как запрос или ответ (0, 1): {self._config.QR}')

        if self._config.OP_CODE not in OP_VALUES:
            raise CreatorException(
                f'Поле не может быть однозначно идентифицировано как код запроса (0, 1, 2): {self._config.OP_CODE}')

        if self._config.AA not in QR_AA_TC_RD_RA_VALUES:
            raise CreatorException(
                f'Поле не может быть однозначно идентифицировано как код авторитета (0, 1): {self._config.AA}')

        if self._config.TC not in QR_AA_TC_RD_RA_VALUES:
            raise CreatorException(
                f'Поле не может быть однозначно идентифицировано как код обрезки пакета (0, 1): {self._config.TC}')

        if self._config.RD not in QR_AA_TC_RD_RA_VALUES:
            raise CreatorException(
                f'Поле не может быть однозначно идентифицировано как код желания рекурсии (0, 1): {self._config.RD}')

        if self._config.RA not in QR_AA_TC_RD_RA_VALUES:
            raise CreatorException(
                f'Поле не может быть однозначно идентифицировано как код возможности рекурсии (0, 1): {self._config.RA}')

        if self._config.Z > MAX_Z:
            raise CreatorException(
                f"Значение в поле не может быть больше 7 из-за размерности поля в 3 бита {self._config.Z}")

        if self._config.RCODE not in RCODE_VALUES:
            raise CreatorException(
                f"Поле не может быть однозначно идентифицировано как статус выполнения запроса (0, 1, 2, 3, 4, 5) {self._config.RCODE}")

        qr_bits: str = str(self._config.QR)
        op_code_bits: str = bin(self._config.OP_CODE)[BIN_OFFSET:].zfill(OP_CODE_SIZE)
        aa_bits: str = str(self._config.AA)
        tc_bits: str = str(self._config.TC)
        rd_bits: str = str(self._config.RD)
        ra_bits: str = str(self._config.RA)
        z_bits: str = bin(self._config.Z)[BIN_OFFSET:].zfill(Z_SIZE)
        rcode_bits: str = bin(self._config.RCODE)[BIN_OFFSET:].zfill(RCODE_SIZE)
        flags = int(qr_bits + op_code_bits + aa_bits + tc_bits + rd_bits + ra_bits + z_bits + rcode_bits, 2)

        bytes_packet += struct.pack('!H', flags)
        bytes_packet += struct.pack('!HHHH', len(self._config.QUERIES), len(self._config.ANSWERS), len(self._config.AUTHORITY), len(self._config.ADDITIONAL))

        query_bits: bytes = b''

        seek = HEADER_SIZE

        for record in self._config.QUERIES:
            encoded_qname = convert_name_to_bits(record.qname, names_minder, seek)

            seek = encoded_qname[1]
            query_bits += encoded_qname[0]

            query_bits += struct.pack('!HH', MAPPER_INVERSE_TYPE_RECORD[record.type_record], MAPPER_INVERSE_CLASS_RECORD[record.class_record])
            seek += 32

        answer_bits, seek = answer_to_bits(self._config.ANSWERS, names_minder, seek)
        authority_bits, seek = answer_to_bits(self._config.AUTHORITY, names_minder, seek)
        additional_bits, seek = answer_to_bits(self._config.ADDITIONAL, names_minder, seek)

        bytes_packet += query_bits + answer_bits + authority_bits + additional_bits

        return bytes_packet
