import unittest

from src.task2.dns_packets.dns_packet_parser import DNSParser


class TestRecordCNAME(unittest.TestCase):
    bytes_stream = b'399181800001000100000000037777770766697265666f7803636f6d0000050001c00c000500010000012c0014086678632d70726f64036d6f7a05776f726b7300'
    parsed_packet = DNSParser(bytes_stream)

    def test_name(self):
        current_name_list = list(map(lambda answer: answer.name, self.parsed_packet.answers_list))
        expected = ['www.firefox.com']
        self.assertEqual(current_name_list, expected)

    def test_type_record(self):
        current_type_record = list(map(lambda answer: answer.type_record, self.parsed_packet.answers_list))
        expected = ['CNAME']
        self.assertEqual(current_type_record, expected)

    def test_class_record(self):
        current_class_record = list(map(lambda answer: answer.class_record, self.parsed_packet.answers_list))
        expected = ['IN']
        self.assertEqual(current_class_record, expected)

    def test_ttl(self):
        current_ttl = list(map(lambda answer: answer.ttl, self.parsed_packet.answers_list))
        expected = [300]
        self.assertEqual(current_ttl, expected)

    def test_rd_len(self):
        current_rd_length = list(map(lambda answer: answer.rd_len, self.parsed_packet.answers_list))
        expected = [160]
        self.assertEqual(current_rd_length, expected)

    def test_cname(self):
        current_cname = list(map(lambda answer: answer.rdata.cname, self.parsed_packet.answers_list))
        expected = ['fxc-prod.moz.works']
        self.assertEqual(current_cname, expected)
