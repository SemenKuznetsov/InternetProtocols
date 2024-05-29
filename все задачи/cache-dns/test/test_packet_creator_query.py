import unittest

from dns_packets.config_dns import DNSConfig
from dns_packets.dns_packet_creator import DNSCreator
from dns_packets.dns_packet_parser import DNSParser
from typeclasses.parser_typeclasses.record_query import Query


class TestQuery(unittest.TestCase):
    bytes_stream = b'da0481800001000200000000076d6f7a696c6c610e636c6f7564666c6172652d646e7303636f6d0000010001c00c00010001000000640004ac402904c00c00010001000000640004a29f3d04'
    parsed_packet = DNSParser(bytes_stream)
    dns_config: DNSConfig = DNSConfig()
    dns_config.ID = int('5f49', 16)
    dns_config.QR = 0
    dns_config.OP_CODE = 0
    dns_config.AA = 0
    dns_config.TC = 0
    dns_config.RD = 1
    dns_config.RA = 0
    dns_config.Z = 0
    dns_config.ANCOUNT = 0
    dns_config.ARCOUNT = 0
    dns_config.NSCOUNT = 0
    dns_config.QDCOUNT = 1
    dns_config.RCODE = 0
    query = Query('google.com', 'A', 'IN')
    dns_config.QUERIES = [query]

    def test_create_query(self):
        bytes_stream = '5f490100000100000000000006676f6f676c6503636f6d0000010001'
        encoded_stream = DNSCreator(self.dns_config).to_bin()
        self.assertEqual(bytes_stream, encoded_stream)


