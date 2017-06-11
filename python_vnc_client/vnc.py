
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

    KEY_BACK_SPACE = 0xFF08
    KEY_TAB = 0xFF09
    KEY_RETURN = 0xFF0D
    KEY_ESCAPE = 0xFF1B
    KEY_INSERT = 0xFF63
    KEY_DELETE = 0xFFFF
    KEY_HOME = 0xFF50
    KEY_END = 0xFF57
    KEY_PAGE_UP = 0xFF55
    KEY_PAGE_DOWN = 0xFF56
    KEY_LEFT = 0xFF51
    KEY_UP = 0xFF52
    KEY_RIGHT = 0xFF53
    KEY_DOWN = 0xFF54
    KEY_F1 = 0xFFBE
    KEY_F2 = 0xFFBF
    KEY_F3 = 0xFFC0
    KEY_F4 = 0xFFC1
    KEY_F5 = 0xFFC2
    KEY_F6 = 0xFFC3
    KEY_F7 = 0xFFC4
    KEY_F8 = 0xFFC5
    KEY_F9 = 0xFFC6
    KEY_F10 = 0xFFC7
    KEY_F11 = 0xFFC8
    KEY_F12 = 0xFFC9
    KEY_SHIFT_LEFT = 0xFFE1
    KEY_SHIFT_RIGHT = 0xFFE2
    KEY_CONTROL_LEFT = 0xFFE3
    KEY_CONTROL_RIGHT = 0xFFE4
    KEY_META_LEFT = 0xFFE7
    KEY_META_RIGHT = 0xFFE8
    KEY_ALT_LEFT = 0xFFE9
    KEY_ALT_RIGHT = 0xFFEA

    def __init__(self, url, port=5900, password=None):
        self._url = url
        self._port = port
        self._password = password
        self._socket = None
        self._image_mutex = threading.Lock()
        self._image_cv = threading.Condition(self._image_mutex)

        self._security_type = None
        self._server_name = ""
        self._receive_thread = None
        self._framebuffer_request = False

        self.__state = "init"

    @property
    def security_type(self):
        return self._security_type

    @property
    def server_name(self):
        return self._server_name

    def connect(self):
        if self._socket is not None:
            raise RuntimeError("socket is already opened.")
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._url, self._port))

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
        if self._password is None:
            if self.SECURITY_TYPE_NONE not in security_types:
                raise RuntimeError("Security type 'None' is not supported by the server.")
            self._security_type = self.SECURITY_TYPE_NONE
        else:
            if self.SECURITY_TYPE_VNC not in security_types:
                raise RuntimeError("Security type VNC is not supported by the server.")
            self._security_type = self.SECURITY_TYPE_VNC
        self.send(struct.pack("B", self._security_type))

        if self._security_type == self.SECURITY_TYPE_NONE:
            pass
        elif self._security_type == self.SECURITY_TYPE_VNC:
            challenge = self.recv(16)
            response = self.encrypt(self._password, challenge)
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
        self._server_name = self.receive_string()

        self.__state = "connected"
        self.start_receive_thread()
        self.update_whole_framebuffer(False)

    def connect_old(self):
        if self._socket is not None:
            raise RuntimeError("socket is already opened.")
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._url, self._port))

        version = self.recv(12)
        match_data = re.match(self.VERSION_PATTERN, version)
        if not match_data or match_data.group(1) not in self.KNOWN_VERSIONS:
            raise RuntimeError("Unknown RFB Protocol version")
        self.send(b"RFB " + b"003.003" + b"\n")

        # Security Type.
        (security_type, ) = struct.unpack(">L", self.recv(4))
        self._security_type = security_type

        if self._security_type == self.SECURITY_TYPE_NONE:
            pass
        elif self._security_type == self.SECURITY_TYPE_VNC:
            challenge = self.recv(16)
            response = self.encrypt(self._password, challenge)
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
        self._server_name = self.receive_string()

        self.__state = "connected"
        self.start_receive_thread()
        self.update_whole_framebuffer(False)

    def close(self):
        if self._socket:
            self.__state = "closing"
            self._socket.shutdown(socket.SHUT_RDWR)
            if self._receive_thread:
                self._receive_thread.join()
            self._socket.close()
            self._socket = None
            self.__state = "closed"
        self._receive_thread = None

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
        if self._socket is None:
            raise RuntimeError("socket is closed.")
        totalsent = 0
        length = len(packet)
        while totalsent < length:
            sent = self._socket.send(packet[totalsent:])
            if sent == 0:
                raise RuntimeError("socket is broken")
            totalsent += sent

    def recv(self, length):
        if self._socket is None:
            raise RuntimeError("socket is closed.")
        totalreceived = 0
        received_data = b""
        while totalreceived < length:
            chunk = self._socket.recv(length - totalreceived)
            if chunk == b"":
                if self.__state == "closing":
                    return None
                raise RuntimeError("socket is broken.")
            received_data += chunk
            totalreceived += len(chunk)
        return received_data

    def key_down(self, key):
        self.key_event(key, 1)

    def key_up(self, key):
        self.key_event(key, 0)

    def key_event(self, key, down):
        if isinstance(key, str):
            key = ord(key)
        packet = struct.pack(">BBxxL", 4, down, key)
        self.send(packet)

    def capture_screen(self, force_update=False):
        if force_update:
            self.update_whole_framebuffer(False)
        else:
            self.update_whole_framebuffer(True)
        with self._image_mutex:
            return tuple(map(tuple, self._image))

    def update_whole_framebuffer(self, incremental=True):
        if incremental:
            packet = struct.pack("BBHHHH", 3, 1, 0, 0, self._width, self._height)
        else:
            packet = struct.pack("BBHHHH", 3, 0, 0, 0, self._width, self._height)
        self.reset_update_flag()
        self.send(packet)
        self.wait_for_update()

    def reset_update_flag(self):
        with self._image_mutex:
            self._framebuffer_request = True

    def wait_for_update(self):
        with self._image_mutex:
            while self._framebuffer_request == True:
                self._image_cv.wait()

    def start_receive_thread(self):
        self._receive_thread = _VncReceiveThread(self)
        self._receive_thread.start()

    def receive_message(self):
        while True:
            data = self.recv(1)
            if data is None:
                break
            (message_type, ) = struct.unpack("B", data)
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
        with self._image_mutex:
            self._framebuffer_request = False
            self._image_cv.notify_all()

    def process_bell(self):
        pass  # Do nothing

    def read_rect(self):
        x, y, width, height, enc = struct.unpack(">HHHHl", self.recv(12))

        data = self.recv(width * height * self._bits_per_pixel // 8)

        fields = self._ctypes_fields
        class Pixel(self._ctypes_base_class):
            _fields_ = fields
        class Parser(self._ctypes_base_class):
            _fields_ = [("pixel", Pixel * width * height)]
        parser = Parser()
        ctypes.memmove(ctypes.addressof(parser), data, len(data))
        pixel = parser.pixel
        image_matrix = [[(pixel_data.red, pixel_data.green, pixel_data.blue) for pixel_data in pixel_line] for pixel_line in pixel]
        self.update_rect(x, y, width, height, image_matrix)

    def update_rect(self, x, y, width, height, image_matrix):
        with self._image_mutex:
            for i in range(height):
                self._image[y + i][x:(x + width)] = image_matrix[i]

    def receive_string(self):
        (reason_length, ) = struct.unpack(">L", self.recv(4))
        reason_str = ""
        if reason_length > 0:
            reason_str = struct.unpack("%ds" % reason_length, self.recv(reason_length))
        return reason_str

    def parse_server_init(self, server_init):
        w, h, bpp, d, bef, tcf, rm, gm, bm, rs, gs, bs = struct.unpack(">HHBBBBHHHBBB3x", server_init)
        self._width = w
        self._height = h
        self._bits_per_pixel = bpp
        self._depth = d
        self._big_endian_flag = bef
        self._true_colour_flag = tcf
        self._red_max = rm
        self._green_max = gm
        self._blue_max = bm
        self._red_shift = rs
        self._green_shift = gs
        self._blue_shift = bs

        self._image = [[(0, 0, 0) for _ in range(w)] for _ in range(h)]

        self.construct_parser()

    def construct_parser(self):
        members = sorted([("red", self._red_shift, self._red_max),
                          ("green", self._green_shift, self._green_max),
                          ("blue", self._blue_shift, self._blue_max)],
                         key=lambda x: x[1])

        if self._bits_per_pixel == 8:
            ctype = ctypes.c_byte
        elif self._bits_per_pixel == 16:
            ctype = ctypes.c_uint16
        elif self._bits_per_pixel == 32:
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
        if bit != self._bits_per_pixel:
            fields.append(("pad%d" % bit, ctype, self._bits_per_pixel - bit))
        self._ctypes_fields = fields

        if self._big_endian_flag:
            self._ctypes_base_class = ctypes.BigEndianStructure
        else:
            self._ctypes_base_class = ctypes.LittleEndianStructure
