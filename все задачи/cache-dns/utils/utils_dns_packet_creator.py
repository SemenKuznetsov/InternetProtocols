import struct

from exceptions.creator_exception import CreatorException
from typeclasses.creator_typeclasses.record_answer import Answer

MAPPER_INVERSE_TYPE_RECORD = {'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15, 'TXT': 16, 'AAAA': 28}
MAPPER_INVERSE_CLASS_RECORD = {'IN': 1, 'CS': 2, 'CH': 3, 'HS': 4}

BIN_OFFSET = 2
MAX_ID = 65535
ID_SIZE = 16
OP_CODE_SIZE = 4
Z_SIZE = 3
RCODE_SIZE = 4
QDCOUNT = ANCOUNT = NSCOUNT = ARCOUNT = 16
MAX_Z = 7
QR_AA_TC_RD_RA_VALUES = [0, 1]
OP_VALUES = [0, 1, 2]
RCODE_VALUES = [0, 1, 2, 3, 4, 5]
ZIPPED_LABEL_SIZE = 14
SIMPLE_LABEL_SIZE = 6
CH_SIZE = 8
HEADER_SIZE = 96
SIMPLE_LABEL = '00'
ZIPPED_LABEL = '11'
NAME_SPLITTER = '.'
TERMINATORS_NULL = '0' * 8


def answer_to_bits(answers: list[Answer], names_minder: {}, init_seek: int) -> tuple[bytes, int]:
    ans_bits = b''
    seek = init_seek
    if answers:
        for ans in answers:
            encoded_name = convert_name_to_bits(ans.name, names_minder, seek)
            seek = encoded_name[1]

            ans_bits += encoded_name[0] + struct.pack('!HH', MAPPER_INVERSE_TYPE_RECORD[ans.type_record],
                                                      MAPPER_INVERSE_CLASS_RECORD[ans.class_record])
            seek += 32

            if ans.ttl > 2 ** 32 - 1:
                raise CreatorException(f'TTL не может быть выше макс значения({2 ** 32 - 1}):{ans.ttl}')

            ans_bits += struct.pack('!I', ans.ttl)
            seek += 48

            rd_data = b''

            match ans.type_record:
                case 'A':
                    encoded_rd_data: bytes = ans.rdata.to_bin(seek)
                    rd_data = encoded_rd_data[0]
                    seek = encoded_rd_data[1]
                case 'AAAA':
                    encoded_rd_data: bytes = ans.rdata.to_bin(seek)
                    rd_data = encoded_rd_data[0]
                    seek = encoded_rd_data[1]
                case 'CNAME':
                    encoded_rd_data = ans.rdata.to_bin(names_minder, seek)
                    rd_data = encoded_rd_data[0]
                    seek = encoded_rd_data[1]
                case 'MX':
                    encoded_rd_data = ans.rdata.to_bin(names_minder, seek)
                    rd_data = encoded_rd_data[0]
                    seek = encoded_rd_data[1]
                case 'NS':
                    encoded_rd_data = ans.rdata.to_bin(names_minder, seek)
                    rd_data = encoded_rd_data[0]
                    seek = encoded_rd_data[1]
                case 'PTR':
                    encoded_rd_data = ans.rdata.to_bin(names_minder, seek)
                    rd_data = encoded_rd_data[0]
                    seek = encoded_rd_data[1]
                case 'SOA':
                    encoded_rd_data = ans.rdata.to_bin(names_minder, seek)
                    rd_data = encoded_rd_data[0]
                    seek = encoded_rd_data[1]

            size_rdata_bytes = len(rd_data)
            rd_len_bits = struct.pack('!H', size_rdata_bytes)
            ans_bits += rd_len_bits + rd_data
            seek += len(rd_data)

    return ans_bits, seek


def convert_name_to_bits(qname: str, names_minder: dict, init_seek: int) -> tuple[bytes, int]:
    seek = init_seek
    query_bits: bytes = b''

    if qname in names_minder:
        label = ZIPPED_LABEL
        pointer = bin(names_minder[qname])[BIN_OFFSET:].zfill(ZIPPED_LABEL_SIZE)
        seek += len(label) + len(pointer)
        query_bits += struct.pack('!H', int(label + pointer, 2))
    else:
        names_minder[qname] = int(seek / 8)
        for section in qname.split(NAME_SPLITTER):
            label = SIMPLE_LABEL
            size_name = bin(len(section))[BIN_OFFSET:].zfill(SIMPLE_LABEL_SIZE)
            encoded_name = section.encode()
            query_bits += struct.pack('!B', int(label + size_name, 2)) + encoded_name
            seek += len(size_name) + len(label) + len(section)

        query_bits += struct.pack('!B', 0)
        seek += 8

    return query_bits, seek
