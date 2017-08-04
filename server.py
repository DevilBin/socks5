#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import select
import socketserver, struct

VERSION = 0x05
CONNECT = 0x01
IPV4    = 0x01
IPV6    = 0x06
DOMAIN  = 0x03
BUFF_SIZE = 4096
AUTH_CODE = b"\x02"
USERNAME  = b"test"
PASSWD    = b"test"


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class Socks5Server(socketserver.StreamRequestHandler):

    def select_method(self):
        sock = self.connection
        ret = sock.recv(BUFF_SIZE)
        if ret[0] != VERSION:
            sock.send(b"\x05\xff")
            return False
        sock.send(b"\x05"+AUTH_CODE)
        return True

    def auth_passwd(self):
        sock = self.connection
        ret = sock.recv(BUFF_SIZE)
        if len(ret):
            user_len, user_name = int(ret[1]), ret[2:2+int(ret[1])]
            password_len, password = int(ret[2+user_len]), ret[3+user_len:]
            if USERNAME == user_name and PASSWD == password:
                sock.send(b"\x01\x00")
                return True
        sock.send(b"\x01\x01")
        return False

    def parse_command(self):
        sock = self.connection
        ret = sock.recv(BUFF_SIZE)
        ver, cmd, rsv, atyp = struct.unpack(">BBBB", ret[:4])
        if ver != VERSION or cmd != CONNECT or atyp == IPV6:
            return False
        if atyp == IPV4:
            addr = socket.inet_ntoa(ret[4:8])
            port = struct.unpack(">H", ret[8:10])
        elif atyp == DOMAIN:
            domain_len = int(ret[4])
            addr = ret[5:5+domain_len]
            port = struct.unpack(">H", ret[5+domain_len: 7+domain_len])
        reply = b"\x05\x00\x00\x01"
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((addr, port[0]))
            print("[I]: Tcp connect to (\'{0}\', {1})".format(addr, port[0]))
            local = remote.getsockname()
            reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
        except socket.error:
            reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
        sock.send(reply)
        if reply[1] == 0:  # Success
            self.forward(sock, remote)
        return True

    @staticmethod
    def forward(sock, remote):
        fd_set = [sock, remote]
        while True:
            r, w, e = select.select(fd_set, [], [])
            if sock in r:
                if remote.send(sock.recv(BUFF_SIZE)) <= 0:
                    break
            if remote in r:
                if sock.send(remote.recv(BUFF_SIZE)) <= 0:
                    break

    def handle(self):
        try:
            print("[I]: Socks connection from", self.client_address)
            self.timeout = 10
            if not self.select_method():
                print("[E]: Select methond error.")
                return False
            if AUTH_CODE == b"\x02" and not self.auth_passwd():
                print("[E]: Auth methond error.")
                return False
            if not self.parse_command():
                print("[E]: Parse methond error.")
                return False
        except socket.error as e:
            self.finish()
            print("[E]: Socket error. {0}".format(e))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:{0} <proxy_port>".format(sys.argv[0]))
        print("Option:")
        print(" <proxy_port> --which port of this proxy server will listen.")
    else:
        server = ThreadingTCPServer(('', int(sys.argv[1])), Socks5Server)
        server.serve_forever()
