import argparse
import socket
from ipwhois import IPWhois, exceptions
from time import time
from scapy.all import sr1
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
import itertools


class Traceroute:
    def __init__(self, host_ip, timeout, port, ttl, verbose, protocol, is_addr_IPv6):
        self.is_ip_IPv6 = is_addr_IPv6
        self.ip = host_ip
        self.timeout = timeout
        self.port = port
        self.TTL = ttl
        self.verbose = verbose
        if (protocol == 'tcp'): self.func = self.make_tcp
        elif (protocol == 'udp'): self.func = self.make_udp
        else: self.func = self.make_icmp

    def run(self):
        num_print = make_num_print()
        as_param = ''
        for ttl in range(1, self.TTL):
            get_package_func = self.func(ttl)
            start_time = time()
            rep = sr1(get_package_func, verbose=0, retry=-2, timeout=self.timeout)
            end_time = round((time() - start_time) * 1000)
            if self.verbose:
                if ttl == 1:
                    continue
                try:
                    if (rep is not None):
                        as_param = IPWhois(rep.src).lookup_whois()['asn']
                except exceptions.IPDefinedError as e:
                    as_param = 'Not found'
            if rep is None:
                num_print('{0} {1}'.format('*', 'timeout'))
                break
            elif rep.haslayer(TCP) or rep.haslayer(UDP) or (rep.type == 3) or (rep.type == 0) or (rep.type == 1):
                num_print('{0} {1} {2} {3} {4}'.format("Done!", rep.src, end_time, 'ms', as_param))
                break
            else:
                num_print('{0} {1} {2} {3}'.format(rep.src, end_time, 'ms', as_param))


    def make_tcp(self, i):
        if self.is_ip_IPv6:
            return IPv6(dst=self.ip, hlim=i) / TCP(dport=self.port)
        return IP(dst=self.ip, ttl=i) / TCP(dport=self.port)

    def make_udp(self, i):
        if self.is_ip_IPv6:
            return IPv6(dst=self.ip, hlim=i) / UDP(dport=self.port)
        return IP(dst=self.ip, ttl=i) / UDP(dport=self.port)

    def make_icmp(self, i):
        if self.is_ip_IPv6:
            return IPv6(dst=self.ip, hlim=i) / ICMPv6EchoRequest()
        return IP(dst=self.ip, ttl=i) / ICMP(type=8)



def make_num_print():
    c = itertools.count(start=1)
    
    def num_print(*args, **kwargs):
        kwargs_copy = dict(kwargs)
        kwargs_copy.update(end=' ', flush=False)
        print(f'{next(c)} ', **kwargs_copy)
        print(*args, **kwargs)

    return num_print

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='timeout', required=False, type=float,
                        default=2, help='таймаут ожидания ответа (по умолчанию 2с)')

    parser.add_argument('-p', dest='port', type=int, default=80,
                        required=False, help='порт (для tcp или udp)')

    parser.add_argument('-n', dest='ttl', type=int, default=128,
                        required=False, help='максимальное количество запросов (TTL)')

    parser.add_argument('-v', dest='verbose', action='store_true', default=False, required=False, help='нужен ли вывод номера автономной системы для каждого ip-адреса')

    parser.add_argument('address', type=str)

    parser.add_argument(dest='protocol', choices=['tcp', 'udp', 'icmp'])

    args = parser.parse_args()

    if ':' in args.address:
        ip = args.address
        is_ip_IPv6 = True
    else:
        ip = socket.gethostbyname(args.address)
        is_ip_IPv6 = False

    traceroute = Traceroute(ip, args.timeout, args.port, args.ttl, args.verbose, args.protocol, is_ip_IPv6)
    traceroute.run()