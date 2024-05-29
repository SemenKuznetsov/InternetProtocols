import unittest

from dns_packets.dns_packet_parser import DNSParser


class TestRecordAAAA(unittest.TestCase):
    bytes_stream = b'09ed81800001000200000000076d6f7a696c6c610e636c6f7564666c6172652d646e7303636f6d00001c0001c00c001c00010000004800102a0698c1005200000000000000000004c00c001c00010000004800102803f800005300000000000000000004'
    parsed_packet = DNSParser(bytes_stream)

    def test_name(self):
        current_name_list = list(map(lambda answer: answer.name, self.parsed_packet.answers_list))
        expected = ['mozilla.cloudflare-dns.com', 'mozilla.cloudflare-dns.com']
        self.assertEqual(current_name_list, expected)

    def test_type_record(self):
        current_type_record = list(map(lambda answer: answer.type_record, self.parsed_packet.answers_list))
        expected = ['AAAA', 'AAAA']
        self.assertEqual(current_type_record, expected)

    def test_class_record(self):
        current_class_record = list(map(lambda answer: answer.class_record, self.parsed_packet.answers_list))
        expected = ['IN', 'IN']
        self.assertEqual(current_class_record, expected)

    def test_ttl(self):
        current_ttl = list(map(lambda answer: answer.ttl, self.parsed_packet.answers_list))
        expected = [72, 72]
        self.assertEqual(current_ttl, expected)

    def test_rd_len(self):
        current_rd_length = list(map(lambda answer: answer.rd_len, self.parsed_packet.answers_list))
        expected = [128, 128]
        self.assertEqual(current_rd_length, expected)

    def test_rdata(self):
        current_rdata = list(map(lambda answer: answer.rdata.ip, self.parsed_packet.answers_list))
        expected = ['2a06:98c1:52:0:0:0:0:4', '2803:f800:53:0:0:0:0:4']
        self.assertEqual(current_rdata, expected)
