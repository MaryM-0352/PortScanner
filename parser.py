import socket
import sys
from argparse import ArgumentParser
from dataclasses import dataclass


@dataclass
class Parser:
    PARSER = ArgumentParser("Port-Scanner")
    PARSER.add_argument(dest='host',
                        type=str,
                        help='host that you want to scan')
    PARSER.add_argument(dest='start_port',
                        type=int,
                        default=1,
                        help='beginning of port range')
    PARSER.add_argument(dest='end_port',
                        type=int,
                        default=100,
                        help='ending of port range')
    ARGS = PARSER.parse_args()

    def __init__(self):
        self.correct_args = Parser.check_input()

    @staticmethod
    def check_input():
        start = Parser.ARGS.start_port
        end = Parser.ARGS.end_port
        host = Parser.ARGS.host
        if start > end:
            print("incorrect input")
            sys.exit()
        if start >= 65535:
            print("start port can't be so large")
            sys.exit()
        try:
            socket.gethostbyname(host)
        except:
            print("invalid hostname")
        return start, end, host
