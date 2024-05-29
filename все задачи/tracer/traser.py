from scapy.all import sr1, socket
from scapy.layers.inet import IP, UDP
import argparse
import prettytable


def trace_step(ip, ttl, max_hops, ip_list, timeout):
    if ttl > max_hops:
        return ip_list

    p = IP(dst=ip, ttl=ttl) / UDP(dport=33434)
    reply = sr1(p, timeout=timeout, verbose=False)

    if reply:
        ip_list.append(reply.src)
        if reply.type == 3:
            return ip_list
    return trace_step(ip, ttl + 1, max_hops, ip_list, timeout)


def traceroute(dst: str, max_hops: int = 30, timeout: int = 1) -> list[str]:
    ip = socket.gethostbyname(dst)
    ttl = 1
    ip_list: list = []
    ip_list: list = trace_step(ip, ttl, max_hops, ip_list, timeout)

    ip_list.append(ip)
    return ip_list


def whois(list_of_ip: list[str]) -> dict[str, dict[str, str]]:
    DEFAULT_REGISTRY_LIST = ['ripe', 'arin', 'apnic', 'afrinic', 'lacnic']
    DEFAULT_PORT = 43

    def parse_ripe_apnic_afrinic(res: str) -> dict[str, str]:
        info = {}
        for line in res.splitlines():
            if (line.startswith('descr:') and
                    len(line[len('descr:'):].strip()) > 0):
                info['Description'] = line[len('descr:'):].strip()
            if (line.startswith('country:') and
                    len(line[len('country'):].strip()) > 0):
                info['Country'] = line[len('country:'):].strip()
            if (line.startswith('origin:') and
                    len(line[len('origin:'):].strip()) > 0):
                info['AS'] = line[len('origin:'):].strip()

        return info if len(info) == 3 else None

    def parse_arin(res: str) -> dict[str, str]:
        info = {}

        for line in res.splitlines():
            if (line.startswith('OrgName:') and
                    len(line[len('OrgName:'):].strip()) > 0):
                info["Description"] = line[len('OrgName:'):].strip()
            if (line.startswith('Country:') and
                    len(line[len('Country:'):].strip()) > 0):
                info["Country"] = line[len('Country:'):].strip()
            if (line.startswith('OriginAS:') and
                    len(line[len('OriginAS:'):].strip()) > 0):
                info["AS"] = line[len('OriginAS:'):].strip()

        return info if len(info) == 3 else None

    def parse_lacnic(res: str) -> dict[str, str]:
        info = {}
        for line in res.splitlines():
            if (line.startswith('owner:') and
                    len(line[len('owner:'):].strip()) > 0):
                info['Description'] = line[len('owner:'):].strip()
            if (line.startswith('country:') and
                    len(line[len('country:'):].strip()) > 0):
                info['Country'] = line[len('country:'):].strip()
            if (line.startswith('aut-num:') and
                    len(line[len('aut-num'):].strip()) > 0):
                info["AS"] = line[len('aut-num:'):].strip()

        return info if len(info) == 3 else None

    def parse_by_registry(registry: str, res: str) -> dict[str, str]:
        return parse_map[registry](res)

    parse_map = {DEFAULT_REGISTRY_LIST[0]: parse_ripe_apnic_afrinic,
                 DEFAULT_REGISTRY_LIST[1]: parse_arin,
                 DEFAULT_REGISTRY_LIST[2]: parse_ripe_apnic_afrinic,
                 DEFAULT_REGISTRY_LIST[3]: parse_ripe_apnic_afrinic,
                 DEFAULT_REGISTRY_LIST[4]: parse_lacnic}

    def get_info_by_ip(ip: str) -> dict[str, str]:
        for registry in DEFAULT_REGISTRY_LIST:
            response_data = ""
            registry_address = f"whois.{registry}.net"
            sock = socket.create_connection((registry_address, DEFAULT_PORT))
            sock.sendall(f'{ip}\n'.encode("utf-8"))

            while True:
                buffer_data = sock.recv(1024).decode("utf-8")
                response_data += buffer_data
                if len(buffer_data) == 0:
                    break
            result = parse_by_registry(registry, response_data)

            if result:
                return result
        return {"Description": "", "Country": "", "AS": ""}

    def get_info_for_ip_list() -> dict[str, dict[str, str]]:
        response_data = {}
        for ip in list_of_ip:
            response_data[ip] = get_info_by_ip(ip)
        return response_data

    return get_info_for_ip_list()


def main():
    parser = argparse.ArgumentParser(prog='tracer',
                                     description='Trace to IP and do Whois for each IP in the trace path.')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    args = parser.parse_args()

    table = prettytable.PrettyTable()
    table.field_names = ['IP', 'AS', 'Country', 'Description']

    trace = traceroute(args.dst_ip)
    w = whois(trace)

    for ip, descr in w.items():
        table.add_row([ip, descr['AS'], descr['Country'], descr['Description']])

    print(table)


if __name__ == "__main__":
    main()
