
import socket
import re
import struct
import threading
import ctypes
from . import pydes

class _VncReceiveThread(threading.Thread):
    def __init__(self, vnc):
        super(_VncReceiveThread, self).__init__()
        self.vnc = vnc

    def run(self):
        self.vnc.receive_message()

class Vnc(object):
    VERSION_PATTERN = re.compile(br"^RFB ([0-9]{3}\.[0-9]{3})" + b"\n$")
    KNOWN_VERSIONS = (b"003.008",)
    CLIENT_VERSION = b"003.008"

    SECURITY_TYPE_NONE = 1
    SECURITY_TYPE_VNC = 2

    SECURITY_RESULT_OK = 0
    SECURITY_RESULT_FAILED = 1

    SERVER_FRAMEBUFFER_UPDATE = 0
    SERVER_SET_COLOUR_MAP_ENTRIES = 1
    SERVER_BELL = 2
    SERVER_SERVER_CUT_TEXT = 3

    def __init__(self, url, port=5900, password=None):
        self.__url = url
        self.__port = port
        self.__password = password
        self.__socket = None
        self.__image_mutex = threading.Lock()
        self.__image_cv = threading.Condition(self.__image_mutex)

        self.__security_type = None
        self.__server_name = ""
        self.__receive_thread = None
        self.__framebuffer_request = False

        self.__state = "init"

    @property
    def security_type(self):
        return self.__security_type

    @property
    def server_name(self):
        return self.__server_name

    def connect(self):
        if self.__socket is not None:
            raise RuntimeError("socket is already opened.")
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((self.__url, self.__port))

        version = self.recv(12)
        match_data = re.match(self.VERSION_PATTERN, version)
        if not match_data or match_data.group(1) not in self.KNOWN_VERSIONS:
            raise RuntimeError("Unknown RFB Protocol version")
        self.send(b"RFB " + self.CLIENT_VERSION + b"\n")

        # Security Type.
        (count, ) = struct.unpack("B", self.recv(1))
        if count == 0:
            reason = self.receive_string()
            raise RuntimeError("Connection refused: %s" % reason)
        security_types = struct.unpack("%dB" % count, self.recv(count))
        if self.__password is None:
            if self.SECURITY_TYPE_NONE not in security_types:
                raise RuntimeError("Security type 'None' is not supported by the server.")
            self.__security_type = self.SECURITY_TYPE_NONE
        else:
            if self.SECURITY_TYPE_VNC not in security_types:
                raise RuntimeError("Security type VNC is not supported by the server.")
            self.__security_type = self.SECURITY_TYPE_VNC
        self.send(struct.pack("B", self.__security_type))

        if self.__security_type == self.SECURITY_TYPE_NONE:
            pass
        elif self.__security_type == self.SECURITY_TYPE_VNC:
            challenge = self.recv(16)
            response = self.encrypt(self.__password, challenge)
            self.send(response)
        else:
            raise NotImplementedError()
        (security_result, ) = struct.unpack(">L", self.recv(4))
        if security_result != self.SECURITY_RESULT_OK:
            reason = self.receive_string()
            raise RuntimeError("Authentication Failed: %s" % reason)

        # ClientInit
        shared = 0
        self.send(struct.pack("B", shared))
        # ServerInit
        server_init = self.recv(20)
        self.parse_server_init(server_init)
        self.__server_name = self.receive_string()

        self.__state = "connected"
        self.start_receive_thread()
        self.update_whole_framebuffer(False)

    def connect_old(self):
        if self.__socket is not None:
            raise RuntimeError("socket is already opened.")
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((self.__url, self.__port))

        version = self.recv(12)
        match_data = re.match(self.VERSION_PATTERN, version)
        if not match_data or match_data.group(1) not in self.KNOWN_VERSIONS:
            raise RuntimeError("Unknown RFB Protocol version")
        self.send(b"RFB " + b"003.003" + b"\n")

        # Security Type.
        (security_type, ) = struct.unpack(">L", self.recv(4))
        self.__security_type = security_type

        if self.__security_type == self.SECURITY_TYPE_NONE:
            pass
        elif self.__security_type == self.SECURITY_TYPE_VNC:
            challenge = self.recv(16)
            response = self.encrypt(self.__password, challenge)
            self.send(response)
        else:
            raise NotImplementedError()
        (security_result, ) = struct.unpack(">L", self.recv(4))
        if security_result != self.SECURITY_RESULT_OK:
            reason = self.receive_string()
            raise RuntimeError("Authentication Failed: %s" % reason)

        # ClientInit
        shared = 0
        self.send(struct.pack("B", shared))
        # ServerInit
        server_init = self.recv(20)
        self.parse_server_init(server_init)
        self.__server_name = self.receive_string()

        self.__state = "connected"
        self.start_receive_thread()
        self.update_whole_framebuffer(False)

    def close(self):
        if self.__socket:
            self.__state = "closing"
            self.__socket.shutdown(socket.SHUT_RDWR)
            if self.__receive_thread:
                self.__receive_thread.join()
            self.__socket.close()
            self.__socket = None
            self.__state = "closed"
        self.__receive_thread = None

    def encrypt(self, password, challenge):
        if isinstance(password, bytes):
            key = password
        else:
            key = password.encode("ascii")

        if isinstance(challenge, bytes):
            text = challenge
        else:
            text = challenge.encode("ascii")

        if len(key) < 8:
            key += b"\0" * (8 - len(key))

        # Pre-process for RFB authentication
        new_key = []
        for ch in struct.unpack("8B", key):
            #              drop "0b" and reverse
            new_ch = bin(ch)[2:][::-1]
            if len(new_ch) < 8:
                new_ch += "0" * (8 - len(new_ch))
            new_key.append(int(new_ch, 2))
        return pydes.des(struct.pack("8B", *new_key)).encrypt(text)

    def send(self, packet):
        if self.__socket is None:
            raise RuntimeError("socket is closed.")
        totalsent = 0
        length = len(packet)
        while totalsent < length:
            sent = self.__socket.send(packet[totalsent:])
            if sent == 0:
                raise RuntimeError("socket is broken")
            totalsent += sent

    def recv(self, length):
        if self.__socket is None:
            raise RuntimeError("socket is closed.")
        totalreceived = 0
        received_data = b""
        while totalreceived < length:
            chunk = self.__socket.recv(length - totalreceived)
            if chunk == b"":
                if self.__state == "closing":
                    return None
                raise RuntimeError("socket is broken.")
            received_data += chunk
            totalreceived += len(chunk)
        return received_data

    def capture_screen(self, force_update=False):
        if force_update:
            self.update_whole_framebuffer(False)
        else:
            self.update_whole_framebuffer(True)
        with self.__image_mutex:
            return tuple(map(tuple, self.__image))

    def update_whole_framebuffer(self, incremental=True):
        if incremental:
            packet = struct.pack("BBHHHH", 3, 1, 0, 0, self.__width, self.__height)
        else:
            packet = struct.pack("BBHHHH", 3, 0, 0, 0, self.__width, self.__height)
        self.reset_update_flag()
        self.send(packet)
        self.wait_for_update()

    def reset_update_flag(self):
        with self.__image_mutex:
            self.__framebuffer_request = True

    def wait_for_update(self):
        with self.__image_mutex:
            while self.__framebuffer_request == True:
                self.__image_cv.wait()

    def start_receive_thread(self):
        self.__receive_thread = _VncReceiveThread(self)
        self.__receive_thread.start()

    def receive_message(self):
        while True:
            data = self.recv(1)
            if data is None:
                break
            (message_type, ) = struct.unpack("B", data)
            print("message: %d" % message_type)
            if message_type == self.SERVER_FRAMEBUFFER_UPDATE:
                self.process_framebuffer_update()
            elif message_type == self.SERVER_SET_COLOUR_MAP_ENTRIES:
                raise NotImplementedError("SetColourMapEntries is not implemented")
            elif message_type == self.SERVER_BELL:
                self.process_bell()
            elif message_type == self.SERVER_SERVER_CUT_TEXT:
                raise NotImplementedError("SetverCutText is not implemented")

    def process_framebuffer_update(self):
        self.recv(1)  # padding
        (num_of_rects, ) = struct.unpack(">H", self.recv(2))
        for _ in range(num_of_rects):
            self.read_rect()
        with self.__image_mutex:
            self.__framebuffer_request = False
            self.__image_cv.notify_all()

    def process_bell(self):
        pass  # Do nothing

    def read_rect(self):
        x, y, width, height, enc = struct.unpack(">HHHHl", self.recv(12))

        data = self.recv(width * height * self.__bits_per_pixel // 8)

        fields = self.__ctypes_fields
        class Pixel(self.__ctypes_base_class):
            _fields_ = fields
        class Parser(self.__ctypes_base_class):
            _fields_ = [("pixel", Pixel * width * height)]
        parser = Parser()
        ctypes.memmove(ctypes.addressof(parser), data, len(data))
        pixel = parser.pixel
        image_matrix = [[(pixel_data.red, pixel_data.green, pixel_data.blue) for pixel_data in pixel_line] for pixel_line in pixel]
        self.update_rect(x, y, width, height, image_matrix)

    def update_rect(self, x, y, width, height, image_matrix):
        with self.__image_mutex:
            for i in range(height):
                self.__image[y + i][x:(x + width)] = image_matrix[i]

    def receive_string(self):
        (reason_length, ) = struct.unpack(">L", self.recv(4))
        reason_str = ""
        if reason_length > 0:
            reason_str = struct.unpack("%ds" % reason_length, self.recv(reason_length))
        return reason_str

    def parse_server_init(self, server_init):
        w, h, bpp, d, bef, tcf, rm, gm, bm, rs, gs, bs = struct.unpack(">HHBBBBHHHBBB3x", server_init)
        self.__width = w
        self.__height = h
        self.__bits_per_pixel = bpp
        self.__depth = d
        self.__big_endian_flag = bef
        self.__true_colour_flag = tcf
        self.__red_max = rm
        self.__green_max = gm
        self.__blue_max = bm
        self.__red_shift = rs
        self.__green_shift = gs
        self.__blue_shift = bs

        self.__image = [[(0, 0, 0) for _ in range(w)] for _ in range(h)]

        self.construct_parser()

    def construct_parser(self):
        members = sorted([("red", self.__red_shift, self.__red_max),
                          ("green", self.__green_shift, self.__green_max),
                          ("blue", self.__blue_shift, self.__blue_max)],
                         key=lambda x: x[1])

        if self.__bits_per_pixel == 8:
            ctype = ctypes.c_byte
        elif self.__bits_per_pixel == 16:
            ctype = ctypes.c_uint16
        elif self.__bits_per_pixel == 32:
            ctype = ctypes.c_uint32
        else:
            raise RuntimeError("Unsupported bits-per-pixel")

        bit_count = {
            0x01: 1,
            0x03: 2,
            0x07: 3,
            0x0F: 4,
            0x1F: 5,
            0x3F: 6,
            0x7F: 7,
            0xFF: 8,
            0x1FF: 9,
            0x3FF: 10,
            0x7FF: 11,
            0xFFF: 12
        }

        fields = []
        bit = 0
        for name, shift, max_value in members:
            if shift != bit:
                fields.append(("pad%d" % bit, ctype, shift - bit))
            fields.append((name, ctype, bit_count[max_value]))
            bit = shift + bit_count[max_value]
        if bit != self.__bits_per_pixel:
            fields.append(("pad%d" % bit, ctype, self.__bits_per_pixel - bit))
        self.__ctypes_fields = fields

        if self.__big_endian_flag:
            self.__ctypes_base_class = ctypes.BigEndianStructure
        else:
            self.__ctypes_base_class = ctypes.LittleEndianStructure
