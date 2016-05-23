# -*- coding: utf-8 -*-
import time, re, gc, traceback, random, json, base64
from pprint import pprint
import hashlib

import logging
import requests
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import os.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

import socket

from binascii import unhexlify
import struct
import tea

from tlv import TLV
from utils import *

class EnvandDevice(object):
    def __init__(self):
        self.imei = '866819027236658'
        self.ver = '5.8.0.157158'
        self.appid = 537042771
        self.pc_ver = '1F 41'
        self.os_type = 'android'
        self.os_version = '4.4.4'
        self.network_type = 2
        self.apn = 'wifi'
        self.device = 'redmi note 3'
        self.apk_id = 'com.tencent.mobileqq'
        self.apk_version = '5.8.0.157158'
        self.apk_sign = bytearray.fromhex('A6 B7 45 BF 24 A2 C2 77 52 77 16 F6 F3 6E B6 8D')
        self.imei_= bytearray.fromhex('38 36 36 38 31 39 30 32 37 32 33 36 36 35 38')

class QQ(EnvandDevice, TLV):  # every qq has an env and device attached
    def __init__(self, username, password):
        EnvandDevice.__init__(self)
        TLV.__init__(self)
        self.username = username
        self.password = password
        self.status = 'init'  # init, logging loggedin

        luin = long(self.username)
        if self.username > 2147483647 :
            luin = struct.pack('!q', luin)
            luin = bytearray( luin )
            self.uin = luin[-4:]
        else :
            luin = struct.pack('!l', luin)
            luin = bytearray( luin )
            self.uin = luin[-4:]
        print 'uin:', ':'.join('{:02x}'.format(d) for d in self.uin)

        self.md5 = md5(self.password)
        self.md5 = bytearray( self.md5 )
        print 'md5:', bytearray_to_hex_string( self.md5 )
        self.md5_2 = md5( self.md5 + bytearray(4) + self.uin )
        self.md5_2 = bytearray( self.md5_2 )
        print 'md52:', bytearray_to_hex_string( self.md5_2 )

        self.ksid = bytearray.fromhex( '93 AC 68 93 96 D5 7E 5F 94 96 B8 15 36 AA FE 91' )

        self.requestid = Seq(start=10000)
        self.pc_sub_cmd = Seq(start=0, end=0x7fff)
        self.token002c = bytearray()
        #self.token002c = bytearray.fromhex('49 9D 9A 3A CB 99 EF 64 AA 0C D5 09 C8 58 B2 D9 0A 4B 83 7B 0A 2D 52 10 FA B8 A8 B9 1E A3 BD 8E 0A 22 C0 F6 B0 57 CE E7 74 EF D0 64 B1 5B 9D 5A 28 BC 43 62 0D 37 6D 36 D8 83 46 18 BE 14 87 32')
        self.token004c = bytearray()
        #self.token004c = bytearray.fromhex('19 04 11 31 AC F1 4A AA 33 67 A8 C3 23 1F 37 A4 A5 BE 8C F7 AB 14 ED AD FF 4B C1 95 1C AF 29 9D 93 F3 7D 6D EF 2B 5A 44 AD FC 36 FA 58 B1 30 8C 7D F6 DE FE B1 D9 03 97 2E 89 50 01 E5 43 5E 97 57 D1 A8 FE 3C B4 EA C5')
        self.key = bytearray(16)
        #self.key = bytearray.fromhex('57 36 70 3F 3B 24 44 73 56 53 73 6D 77 2C 28 79')

        self.sharekey = bytearray().fromhex('957C3AAFBF6FAF1D2C2F19A5EA04E51C')
        self.pubkey = bytearray().fromhex('02244B79F2239755E73C73FF583D4EC5625C19BF8095446DE1')

        self.tgtkey = gen_random_bytearray( 16 )
        self.randkey = gen_random_bytearray( 16 )

        self.con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.con.connect( ('msfwifi.3g.qq.com', 8080) )
        self.con.settimeout( 7 )

    def send(self, data):
        self.requestid.get()
        self.con.send( data )

    def recv(self):
        data = self.con.recv()
        data = bytearray(data)
        print bytearray_to_hex_string(data)
        data = self.unpack( data )
        return data

    def un_pack(self, data):
        data = bytearray(data)
        print bytearray_to_hex_string(data)
        qq_pos = data.find(self.username)

        remain = data[qq_pos+len(self.username):len(data)]
        #print bytearray_to_hex_string(remain)
        return remain
        
    def login(self):
        login_packet = self.pack_login()
        self.con.send( login_packet )
        print 'login packet sent'

        data = self.con.recv(1024)
        print 'login packet response received'
        remain=self.un_pack(data)
        print bytearray_to_hex_string(remain)

        #TODO decrypt failed
        decrypt_data=tea.decrypt(remain, self.sharekey)
        print bytearray_to_hex_string(decrypt_data)

    def pack_pc(self, cmd, b, randkey, pubkey):
        # 02
        # 02 23
        # 1F 41
        # 08 12
        # 00 01
        # 18 B4 A1 BC
        # 03 07 00 00 00 00 02 00 00 00 00 00 00 00 00
        # 01 02
        # FC 20 D9 C0 51 B7 BE A0 70 4D 1E BF BC D6 E7 61 //下面的key
        # 01 02
        # 00 00
        p = qq_bytearray()
        p = p.append_hex( self.pc_ver )
        p = p.append_str( cmd )
        p = p.append_u16( self.pc_sub_cmd.get() )
        p = p.append_str ( self.uin )
        p = p.append_hex ( '03 07 00 00 00 00 02 00 00 00 00 00 00 00 00' )
        if len(pubkey)==0:
            p = p.append_hex( '01 01' )
        else:
            p = p.append_hex( '01 02' )
        p = p.append_str( randkey )
        p = p.append_hex( '01 02' )
        p = p.append_u16( len(pubkey) )
        if len(pubkey)==0:
            p = p.append_zero(2)
        else:
            p = p.append_str( b )
        p = p.append_hex( '03' )

        p = p.insert_u16( len(p) + 3 ) 
        p = p.insert_hex( '02' )
        self.logpacket( 'pack_pc', p )
        return p

    def pack(self, b, t): # b:bytearray | t(type): 0(登陆) 1(上线) 2(上线之后)
        p = qq_bytearray()
        if t==0:
            p = p.append_hex( '00 00 00 08 02 00 00 00 04' )
        elif t==1:
            p = p.append_hex( '00 00 00 08 01 00 00' )
            p = p.append_u16len_plus_4_and_value( self.token002c )
        else:
            p = p.append_hex( '00 00 00 09 01' )
            p.extend( bytearray(struct.pack('!I', self.requestid.get_and_freeze())) )

        p = p.append_zero( 3 )
        p = p.append_u16len_plus_4_and_value( bytearray(self.username) )
        p = p.append_str( b )

        p = p.insert_u32( len(p) + 4 )
        return p

    def unpack(self, data, flag):  # data:bytearray flag:bool
        start = data.index( self.uin )
        data = data[start+4:]
        if flag:
            start = data.index( self.uin )
            data = data[start+4:]

    def Make_login_sendSsoMsg( self, servicecmd, wupbuffer, ext_bin, imei, ksid, ver, islogin):
                              # string     bytearray  bytearray str  str   str   bool
        p = qq_bytearray()
        msgcookies = bytearray.fromhex('B6 CC 78 FC')
        p = p.append_u32( self.requestid.get_and_freeze() )
        p = p.append_u32( self.appid )
        p = p.append_u32( self.appid )
        p = p.append_hex( '01 00 00 00 00 00 00 00 00 00 00 00' )
        p = p.append_u32len_plus_4_and_value( ext_bin )
        p = p.append_u32len_plus_4_and_value( servicecmd )
        p = p.append_u32len_plus_4_and_value( msgcookies )
        p = p.append_u32len_plus_4_and_value( imei )
        p = p.append_u32len_plus_4_and_value( ksid )
        p = p.append_u16len_plus_2_and_value( ver )

        #p = p.append_u32len_plus_4_and_value( p )
        p = p.insert_u32( len(p) + 4 ) 

        p = p.append_u32len_plus_4_and_value( wupbuffer )

        #return self.pack( tea.encrypt(p, self.key), 0 if islogin else 1 )
        return self.pack( tea.encrypt(p, self.key), 1 )
        

    def pack_login(self):
        self.timestamp = qq_timestamp()
        login_packet = qq_bytearray()
        login_packet = login_packet.append_hex( '00 09' )
        login_packet = login_packet.append_u16( 19 )
        login_packet = login_packet.append_str( self.tlv_18(self.uin) )
        login_packet = login_packet.append_str( self.tlv_1(self.uin, self.timestamp) )
        #login_packet = login_packet.append_str( self.tlv_106(self.uin, self.md5, self.md5_2, self.tgtkey, self.imei, self.timestamp, self.appid) )
        login_packet = login_packet.append_str( self.tlv_106(self.uin, self.md5, self.md5_2, self.tgtkey, self.imei_, self.timestamp, self.appid) )
        login_packet = login_packet.append_str( self.tlv_116() )
        login_packet = login_packet.append_str( self.tlv_100(self.appid) )
        login_packet = login_packet.append_str( self.tlv_107() )
        login_packet = login_packet.append_str( self.tlv_108(self.ksid) )
        p_109 = self.tlv_109( self.imei )
        p_124 = self.tlv_124( self.os_type, self.os_version, self.network_type, self.apn )
        p_128 = self.tlv_128( self.device, self.imei_ )
        p_16e = self.tlv_16e( self.device )
        login_packet.extend( self.tlv_144( self.tgtkey, p_109, p_124, p_128, p_16e ) )
        login_packet.extend( self.tlv_142(self.apk_id) )
        login_packet.extend( self.tlv_145(self.imei_) )
        login_packet.extend( self.tlv_154(self.requestid.get_and_freeze()) )
        login_packet.extend( self.tlv_141(self.network_type, self.apn) )
        login_packet.extend( self.tlv_8() )
        login_packet.extend( self.tlv_16b() )
        login_packet.extend( self.tlv_147(self.apk_version, self.apk_sign) )
        login_packet.extend( self.tlv_177() )
        login_packet.extend( self.tlv_187() )
        login_packet.extend( self.tlv_188() )
        login_packet.extend( self.tlv_191() )
        print login_packet
        login_packet = self.pack_pc('08 10', tea.encrypt(login_packet, self.sharekey), self.randkey, self.pubkey)
        return self.Make_login_sendSsoMsg('wtlogin.login', login_packet, bytearray(), self.imei, self.ksid, self.ver, True)
            
def md5(s):
    md5 = hashlib.md5()
    md5.update( s )
    return md5.digest()

def main():
    logging.basicConfig(level=logging.DEBUG,
                        datefmt='%a, %d %b %Y %H:%M:%S'
                       )
    qq = QQ('2373220602', '31415926a')
    qq.login()

if __name__=='__main__':
    main()
