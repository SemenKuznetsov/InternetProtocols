import unittest

from dns_packets.dns_packet_parser import DNSParser


class TestRecordA(unittest.TestCase):
    bytes_stream = b'86ee81800001000200000000076d6f7a696c6c610e636c6f7564666c6172652d646e7303636f6d0000010001c00c00010001000000890004a29f3d04c00c00010001000000890004ac402904'
    parsed_packet = DNSParser(bytes_stream)

    def test_name(self):
        current_name_list = list(map(lambda answer: answer.name, self.parsed_packet.answers_list))
        expected = ['mozilla.cloudflare-dns.com', 'mozilla.cloudflare-dns.com']
        self.assertEqual(current_name_list, expected)

    def test_type_record(self):
        current_type_record = list(map(lambda answer: answer.type_record, self.parsed_packet.answers_list))
        expected = ['A', 'A']
        self.assertEqual(current_type_record, expected)

    def test_class_record(self):
        current_class_record = list(map(lambda answer: answer.class_record, self.parsed_packet.answers_list))
        expected = ['IN', 'IN']
        self.assertEqual(current_class_record, expected)

    def test_ttl(self):
        current_ttl = list(map(lambda answer: answer.ttl, self.parsed_packet.answers_list))
        expected = [137, 137]
        self.assertEqual(current_ttl, expected)

    def test_rd_len(self):
        current_rd_length = list(map(lambda answer: answer.rd_len, self.parsed_packet.answers_list))
        expected = [32, 32]
        self.assertEqual(current_rd_length, expected)

    def test_rdata(self):
        current_rdata = list(map(lambda answer: answer.rdata.ip, self.parsed_packet.answers_list))
        expected = ['162.159.61.4', '172.64.41.4']
        self.assertEqual(current_rdata, expected)
