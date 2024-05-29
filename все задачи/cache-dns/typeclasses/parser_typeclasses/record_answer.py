from typeclasses.parser_typeclasses.record_a import RecordTypeA
from typeclasses.parser_typeclasses.record_aaaa import RecordTypeAAAA
from typeclasses.parser_typeclasses.record_mx import RecordTypeMX
from typeclasses.parser_typeclasses.record_ns import RecordTypeNS
from typeclasses.parser_typeclasses.record_ptr import RecordTypePTR
from typeclasses.parser_typeclasses.record_soa import RecordTypeSoa
from typeclasses.parser_typeclasses.record_cname import RecordTypeCNAME


class Answer:
    def __init__(self, name: str, type_record: str, class_record: str, ttl_sec: int, rd_length: int, rdata):
        self._Name = name
        self._Type_record = type_record
        self._Class_record = class_record
        self._TTL_sec = ttl_sec
        self._RD_length = rd_length
        self._Rdata = rdata

        """
        В поле RDATA лежит уже запись конкретного типа, который определяется полем этого класcа _Type_record
        """

    @property
    def name(self) -> str:
        return self._Name

    @property
    def type_record(self) -> str:
        return self._Type_record

    @property
    def class_record(self) -> str:
        return self._Class_record

    @property
    def ttl(self) -> int:
        return self._TTL_sec

    @property
    def rd_len(self) -> int:
        return self._RD_length

    @property
    def rdata(self) -> RecordTypeA or RecordTypeAAAA or RecordTypeNS or RecordTypePTR or RecordTypeSoa or RecordTypeMX or RecordTypeCNAME:
        return self._Rdata
