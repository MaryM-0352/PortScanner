import socket
import struct
from concurrent.futures.thread import ThreadPoolExecutor

from parser import Parser

PACKAGE = b'\x13' + b'\x00' * 39 + b'\x6f\x89\xe9\x1a\xb6\xd5\x3b\xd3'


class Scanner:
    def __init__(self):
        self.start_port, self.end_port, self.host = Parser().correct_args
        self.defined = []

    def scan_tcp(self, host, port):
        if port not in self.defined:
            answer = ""
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                try:
                    sock.connect((host, port))
                    answer = f"{port} -- tcp"
                except (socket.timeout, socket.error):
                    # print(f'{port} is closed')
                    pass
            if answer:
                protocol = self.define_tcp_protocol(port)
                if protocol:
                    print(f"{answer} -- {protocol}")
                else:
                    print(f"{answer} -- Unknown")

    def scan_udp(self, host, port):
        answer = ""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            try:
                sock.sendto(PACKAGE, (host, port))
                data, _ = sock.recvfrom(1024)
                answer = f"{port} -- udp"
            except (socket.timeout, socket.error):
                # print(f'{port} is closed')
                pass
        if answer:
            protocol = self.define_udp_protocol(data)
            if protocol:
                print(f"{answer} -- {protocol}")
            else:
                print(f"{answer} -- Unknown")
            self.defined.append(port)

    def define_tcp_protocol(self, port) -> str:
        request = self.tcp_request(port)
        if b"HTTP" in request:
            return 'HTTP'
        if b"POP" in request:
            return 'POP3'
        if b"SMTP" in request:
            return 'SMTP'

    def define_udp_protocol(self, data):
        if struct.pack('B', PACKAGE[0]) == struct.pack('B', data[0]):
            return "DNS"
        if PACKAGE[-8:] == data[24:32]:
            return "SNTP"

    def tcp_request(self, port):
        request = r"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n".encode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect((self.host, port))
                sock.sendall(request)
                answer = sock.recv(1024)
            except (socket.timeout, socket.error):
                pass
        return answer

    def work(self, port):
        self.scan_udp(self.host, port)
        self.scan_tcp(self.host, port)

    def run(self):
        with ThreadPoolExecutor(max_workers=100) as thread_pool:
            for port in range(self.start_port, self.end_port + 1):
                thread_pool.submit(self.work, port)


if __name__ == '__main__':
    scanner = Scanner()
    scanner.run()
