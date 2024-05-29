import unittest

from src.task2.dns_packets.dns_packet_parser import DNSParser


class TestResponse(unittest.TestCase):
    bytes_stream = b'da0481800001000200000000076d6f7a696c6c610e636c6f7564666c6172652d646e7303636f6d0000010001c00c00010001000000640004ac402904c00c00010001000000640004a29f3d04'
    parsed_packet = DNSParser(bytes_stream)

    def test_id(self):
        self.assertEqual(self.parsed_packet.id, 55812)

    def test_QR(self):
        self.assertEqual(self.parsed_packet.qr, 1)

    def test_op_code(self):
        self.assertEqual(self.parsed_packet.op_code, 0)

    def test_aa(self):
        self.assertEqual(self.parsed_packet.aa, 0)

    def test_tc(self):
        self.assertEqual(self.parsed_packet.tc, 0)

    def test_rd(self):
        self.assertEqual(self.parsed_packet.rd, 1)

    def test_ra(self):
        self.assertEqual(self.parsed_packet.ra, 1)

    def test_z(self):
        self.assertEqual(self.parsed_packet.z, 0)

    def test_reply(self):
        self.assertEqual(self.parsed_packet.rcode, 0)

    def test_name(self):
        self.assertEqual(self.parsed_packet.queries_list[0].qname, 'mozilla.cloudflare-dns.com')

    def test_type(self):
        self.assertEqual(self.parsed_packet.queries_list[0].type_record, 'A')

    def test_class(self):
        self.assertEqual(self.parsed_packet.queries_list[0].class_record, 'IN')
