import unittest

from dns_packets.dns_packet_parser import DNSParser


class TestRecordPTR(unittest.TestCase):
    bytes_stream = b'7a43818000010001000000000331303003323232033139340331373307696e2d61646472046172706100000c0001c00c000c00010000003f00160a6c6f2d696e2d66313030053165313030036e657400'
    parsed_packet = DNSParser(bytes_stream)

    def test_name(self):
        current_name_list = list(map(lambda answer: answer.name, self.parsed_packet.answers_list))
        expected = ['100.222.194.173.in-addr.arpa']
        self.assertEqual(current_name_list, expected)

    def test_type_record(self):
        current_type_record = list(map(lambda answer: answer.type_record, self.parsed_packet.answers_list))
        expected = ['PTR']
        self.assertEqual(current_type_record, expected)

    def test_class_record(self):
        current_class_record = list(map(lambda answer: answer.class_record, self.parsed_packet.answers_list))
        expected = ['IN']
        self.assertEqual(current_class_record, expected)

    def test_ttl(self):
        current_ttl = list(map(lambda answer: answer.ttl, self.parsed_packet.answers_list))
        expected = [63]
        self.assertEqual(current_ttl, expected)

    def test_rd_len(self):
        current_rd_length = list(map(lambda answer: answer.rd_len, self.parsed_packet.answers_list))
        expected = [176]
        self.assertEqual(current_rd_length, expected)

    def test_name_server(self):
        current_rdata = list(map(lambda answer: answer.rdata.name_server, self.parsed_packet.answers_list))
        expected = ['lo-in-f100.1e100.net']
        self.assertEqual(current_rdata, expected)
