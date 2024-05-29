from __future__ import annotations

import json
import os.path
import time
from json import JSONDecodeError

from typeclasses.creator_typeclasses.record_a import RecordTypeA
from typeclasses.creator_typeclasses.record_aaaa import RecordTypeAAAA
from typeclasses.creator_typeclasses.record_cname import RecordTypeCNAME
from typeclasses.creator_typeclasses.record_mx import RecordTypeMX
from typeclasses.creator_typeclasses.record_ns import RecordTypeNS
from typeclasses.creator_typeclasses.record_ptr import RecordTypePTR
from typeclasses.creator_typeclasses.record_soa import RecordTypeSoa


class Cache:
    def __init__(self):
        self.name_records = {}

    def clean(self) -> None:
        self.name_records.clear()

    def push(self, name: str, type_record: str, rdata, ttl):
        self.name_records[f'{name}|{type_record}'] = (rdata, ttl, int(time.time()))

    def get(self, name: str, type_record: str):
        timer = int(time.time())

        for key, values in self.name_records.copy().items():
            if abs(timer - values[2]) > values[1]:
                self.name_records.pop(key)

        return self.name_records.get(f'{name}|{type_record}')

    def from_json(self, name: str):
        if not os.path.exists(name):
            file = open(name, 'w')
            file.close()

        with open(name, 'r') as file:
            try:
                data: dict = json.load(file)
                for key, value in data.items():
                    type_record = key.split('|')[-1]
                    val = ''
                    match type_record:
                        case 'A':
                            val = (RecordTypeA(value[0]['ip_v4']), value[1], value[2])
                        case 'AAAA':
                            val = (RecordTypeAAAA(value[0]['ip_v6']), value[1], value[2])
                        case 'CNAME':
                            val = (RecordTypeCNAME(value[0]['cname']), value[1], value[2])
                        case 'MX':
                            val = (RecordTypeMX(value[0]['preference'], value[0]['mail_exchange']), value[1], value[2])
                        case 'NS':
                            val = (RecordTypeNS(value[0]['authority_name_server']), value[1], value[2])
                        case 'PTR':
                            val = (RecordTypePTR(value[0]['name']), value[1], value[2])
                        case 'SOA':
                            fields = value[0]
                            val = (RecordTypeSoa(fields['primary_server'], fields['responsible_authority'], fields['serial_number'], fields['refresh_interval'], fields['retry_interval'], fields['expire_limit'], fields['minimum_ttl']), value[1], value[2])

                    self.name_records[key] = val
            except JSONDecodeError:
                return None

    def to_json(self, name: str):
        with open(name, 'w') as file:
            data = self.name_records
            json.dump(data, file, default=lambda x: x.__dict__)
