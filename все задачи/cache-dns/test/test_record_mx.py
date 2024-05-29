import unittest

from dns_packets.dns_packet_parser import DNSParser


class TestRecordMX(unittest.TestCase):
    bytes_stream = b'2fbb8180000100010000000906676f6f676c6503636f6d00000f0001c00c000f0001000000670009000a04736d7470c00cc02a00010001000000340004d155e91ac02a00010001000000340004d155e91bc02a000100010000003400044a7d831ac02a000100010000003400044a7d831bc02a000100010000003400048efb011ac02a001c00010000006700102a00145040100c03000000000000001ac02a001c00010000006700102a00145040100c03000000000000001bc02a001c00010000006700102a00145040100c0e000000000000001ac02a001c00010000006700102a00145040100c0e000000000000001b'
    parsed_packet = DNSParser(bytes_stream)

    def test_name(self):
        current_name_list = list(map(lambda answer: answer.name, self.parsed_packet.answers_list))
        expected = ['google.com']
        self.assertEqual(current_name_list, expected)

    def test_type_record(self):
        current_type_record = list(map(lambda answer: answer.type_record, self.parsed_packet.answers_list))
        expected = ['MX']
        self.assertEqual(current_type_record, expected)

    def test_class_record(self):
        current_class_record = list(map(lambda answer: answer.class_record, self.parsed_packet.answers_list))
        expected = ['IN']
        self.assertEqual(current_class_record, expected)

    def test_ttl(self):
        current_ttl = list(map(lambda answer: answer.ttl, self.parsed_packet.answers_list))
        expected = [103]
        self.assertEqual(current_ttl, expected)

    def test_rd_len(self):
        current_rd_length = list(map(lambda answer: answer.rd_len, self.parsed_packet.answers_list))
        expected = [72]
        self.assertEqual(current_rd_length, expected)

    def test_preference(self):
        current_preference = list(map(lambda answer: answer.rdata.preference, self.parsed_packet.answers_list))
        expected = [10]
        self.assertEqual(current_preference, expected)

    def test_mail_exchange(self):
        current_mx = list(map(lambda answer: answer.rdata.mail_exchange, self.parsed_packet.answers_list))
        expected = ['smtp.google.com']
        self.assertEqual(current_mx, expected)
