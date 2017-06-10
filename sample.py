
import struct
import time
from python_vnc_client.vnc import Vnc

def main():
    vnc = Vnc("localhost", 5900, "!QAZxsw2")
    try:
        vnc.connect()
        image = vnc.capture_screen(False)
        print(image[27][248])
        time.sleep(2)
        image = vnc.capture_screen(False)
        print(image[27][248])
        vnc.key_down(vnc.KEY_ALT_LEFT)
        vnc.key_down(vnc.KEY_TAB)
        time.sleep(0.1)
        vnc.key_up(vnc.KEY_TAB)
        time.sleep(1)
        vnc.key_up(vnc.KEY_ALT_LEFT)
    finally:
        vnc.close()

if __name__ == "__main__":
    main()
