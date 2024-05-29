import unittest

from dns_packets.dns_packet_parser import DNSParser


class TestRecordNS(unittest.TestCase):
    bytes_stream = b'e6d98180000100040000000806676f6f676c6503636f6d0000020001c00c00020001000000c60006036e7333c00cc00c00020001000000c60006036e7332c00cc00c00020001000000c60006036e7334c00cc00c00020001000000c60006036e7331c00cc04c000100010000004b0004d8ef260ac04c001c0001000000a000102001486048020038000000000000000ac05e00010001000000c60004d8ef200ac05e001c0001000000c600102001486048020032000000000000000ac028000100010000004d0004d8ef240ac028001c00010000004d00102001486048020036000000000000000ac03a00010001000000c60004d8ef220ac03a001c0001000000c600102001486048020034000000000000000a'
    parsed_packet = DNSParser(bytes_stream)

    def test_name(self):
        current_name_list = list(map(lambda answer: answer.name, self.parsed_packet.answers_list))
        expected = ['google.com', 'google.com', 'google.com', 'google.com']
        self.assertEqual(current_name_list, expected)

    def test_type_record(self):
        current_type_record = list(map(lambda answer: answer.type_record, self.parsed_packet.answers_list))
        expected = ['NS', 'NS', 'NS', 'NS']
        self.assertEqual(current_type_record, expected)

    def test_class_record(self):
        current_class_record = list(map(lambda answer: answer.class_record, self.parsed_packet.answers_list))
        expected = ['IN', 'IN', 'IN', 'IN']
        self.assertEqual(current_class_record, expected)

    def test_ttl(self):
        current_ttl = list(map(lambda answer: answer.ttl, self.parsed_packet.answers_list))
        expected = [198, 198, 198, 198]
        self.assertEqual(current_ttl, expected)

    def test_rd_len(self):
        current_rd_length = list(map(lambda answer: answer.rd_len, self.parsed_packet.answers_list))
        expected = [48, 48, 48, 48]
        self.assertEqual(current_rd_length, expected)

    def test_name_server(self):
        current_rdata = list(map(lambda answer: answer.rdata.name_server, self.parsed_packet.answers_list))
        expected = ['ns3.google.com', 'ns2.google.com', 'ns4.google.com', 'ns1.google.com']
        self.assertEqual(current_rdata, expected)

