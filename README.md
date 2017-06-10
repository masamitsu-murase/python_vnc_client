
# python\_vnc\_client

This is a VNC client written in pure python.

* This library does not depend on any external libraries.
* This library works fine on both Python 2.7 and Python 3.5.

# Example

```python
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
```

# License

Please use this under MIT License.

Copyright 2017 Masamitsu MURASE

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
