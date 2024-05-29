import unittest

from src.task2.dns_packets.dns_packet_parser import DNSParser


class TestQuery(unittest.TestCase):
    bytes_stream = b'79080100000100000000000006676f6f676c6503636f6d0000010001'
    parsed_packet = DNSParser(bytes_stream)

    def test_id(self):
        self.assertEqual(self.parsed_packet.id, 30984)

    def test_QR(self):
        self.assertEqual(self.parsed_packet.qr, 0)

    def test_op_code(self):
        self.assertEqual(self.parsed_packet.op_code, 0)

    def test_aa(self):
        self.assertEqual(self.parsed_packet.aa, 0)

    def test_tc(self):
        self.assertEqual(self.parsed_packet.tc, 0)

    def test_rd(self):
        self.assertEqual(self.parsed_packet.rd, 1)

    def test_ra(self):
        self.assertEqual(self.parsed_packet.ra, 0)

    def test_z(self):
        self.assertEqual(self.parsed_packet.z, 0)

    def test_reply(self):
        self.assertEqual(self.parsed_packet.rcode, 0)

    def test_qd_count(self):
        self.assertEqual(self.parsed_packet.qdcount, 1)

    def test_an_count(self):
        self.assertEqual(self.parsed_packet.ancount, 0)

    def test_ns_count(self):
        self.assertEqual(self.parsed_packet.nscount, 0)

    def test_ad_count(self):
        self.assertEqual(self.parsed_packet.arcount, 0)