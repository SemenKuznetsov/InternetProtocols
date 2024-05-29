import unittest
from dns_packets.dns_packet_parser import DNSParser


class TestRecordSOA(unittest.TestCase):
    bytes_stream = b'b54d8180000100010004000806676f6f676c6503636f6d0000060001c00c00060001000000050026036e7331c00c09646e732d61646d696ec00c25832c450000038400000384000007080000003cc00c00020001000001130006036e7334c00cc00c00020001000001130002c028c00c00020001000001130006036e7332c00cc00c00020001000001130006036e7333c00cc07a00010001000000520004d8ef220ac07a001c00010000005200102001486048020034000000000000000ac02800010001000000520004d8ef200ac028001c00010000005200102001486048020032000000000000000ac05a00010001000000da0004d8ef260ac05a001c0001000000dd00102001486048020038000000000000000ac08c00010001000000da0004d8ef240ac08c001c0001000000dd00102001486048020036000000000000000a'
    parsed_packet = DNSParser(bytes_stream)

    def test_name(self):
        current_name_list = list(map(lambda answer: answer.name, self.parsed_packet.answers_list))
        expected = ['google.com']
        self.assertEqual(current_name_list, expected)

    def test_type_record(self):
        current_type_record = list(map(lambda answer: answer.type_record, self.parsed_packet.answers_list))
        expected = ['SOA']
        self.assertEqual(current_type_record, expected)

    def test_class_record(self):
        current_class_record = list(map(lambda answer: answer.class_record, self.parsed_packet.answers_list))
        expected = ['IN']
        self.assertEqual(current_class_record, expected)

    def test_ttl(self):
        current_ttl = list(map(lambda answer: answer.ttl, self.parsed_packet.answers_list))
        expected = [5]
        self.assertEqual(current_ttl, expected)

    def test_rd_len(self):
        current_rd_length = list(map(lambda answer: answer.rd_len, self.parsed_packet.answers_list))
        expected = [304]
        self.assertEqual(current_rd_length, expected)

    def test_primary_server(self):
        current_server = list(map(lambda answer: answer.rdata.primary_server, self.parsed_packet.answers_list))
        expected = ['ns1.google.com']
        self.assertEqual(current_server, expected)

    def test_responsible_authority(self):
        current_responsible_authority = list(
            map(lambda answer: answer.rdata.responsible_authority, self.parsed_packet.answers_list))
        expected = ['dns-admin.google.com']
        self.assertEqual(current_responsible_authority, expected)

    def test_serial_number(self):
        current_serial = list(map(lambda answer: answer.rdata.serial_number, self.parsed_packet.answers_list))
        expected = [629353541]
        self.assertEqual(current_serial, expected)

    def test_refresh_interval(self):
        current_refresh_interval = list(map(lambda answer: answer.rdata.refresh_interval, self.parsed_packet.answers_list))
        expected = [900]
        self.assertEqual(current_refresh_interval, expected)

    def test_retry_interval(self):
        current_retry_interval = list(map(lambda answer: answer.rdata.retry_interval, self.parsed_packet.answers_list))
        expected = [900]
        self.assertEqual(current_retry_interval, expected)

    def test_expire_limit(self):
        current_expire_limit = list(map(lambda answer: answer.rdata.expire_limit, self.parsed_packet.answers_list))
        expected = [1800]
        self.assertEqual(current_expire_limit, expected)

    def test_min_ttl(self):
        current_min_ttl = list(map(lambda answer: answer.rdata.minimum_ttl, self.parsed_packet.answers_list))
        expected = [60]
        self.assertEqual(current_min_ttl, expected)
