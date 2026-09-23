"""h2_framing: HTTP/2, as far as a relay that decodes nothing can check it.

A host in the `http2` list is relayed as opaque bytes, so what is checked is
the shape: the 24-byte preface, SETTINGS first on stream 0, and every byte
inside a well-formed frame header. Nothing decodes a payload.
"""

# The HTTP/2 connection preface (RFC 9113 §3.4).
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# A frame header is 9 bytes: 24-bit length, 8-bit type, 8-bit flags, 32-bit
# stream id.
H2_FRAME_HEADER = 9


# The frame a client must send first after the preface, on stream 0 (RFC
# 9113 §3.4).
H2_FRAME_SETTINGS = 0x4


class NotH2(Exception):
    """A connection on an `http2` host is not speaking h2."""


class H2Framing:
    """Whether a guest's byte stream continues to look like HTTP/2 framing.

    Without it an `http2` entry would mean "exempt" rather than "speaks h2".
    The preface does nearly all the work: anything that is not h2 fails on
    its first byte. After the first frame little is caught in flight, since
    a 24-bit length makes almost any bytes parse as a frame; what holds is
    alignment when the connection ends. It is not a conformance checker.
    """

    def __init__(self):
        self._header = bytearray()
        self._payload = 0
        self._first = True

    def feed(self, data: bytes) -> None:
        """Account for bytes going guest -> origin. Raises NotH2."""
        i, n = 0, len(data)
        while i < n:
            if self._payload:
                take = min(self._payload, n - i)
                self._payload -= take
                i += take
                continue
            take = min(H2_FRAME_HEADER - len(self._header), n - i)
            self._header += data[i:i + take]
            i += take
            if len(self._header) < H2_FRAME_HEADER:
                return                  # a header split across two reads
            length = int.from_bytes(self._header[:3], "big")
            kind = self._header[3]
            # The top bit is reserved and receivers must ignore it, so it is
            # masked off rather than refused -- a sender setting it is not
            # something this may fail a connection over.
            stream = int.from_bytes(self._header[5:9], "big") & 0x7FFFFFFF
            self._header.clear()
            if self._first:
                self._first = False
                if kind != H2_FRAME_SETTINGS or stream != 0:
                    raise NotH2(
                        f"the first frame after the preface is type "
                        f"{kind:#04x} on stream {stream}, and RFC 9113 "
                        f"requires SETTINGS on stream 0")
                if length % 6:
                    raise NotH2(
                        f"the opening SETTINGS frame is {length} bytes, which "
                        f"is not a whole number of 6-byte settings")
            self._payload = length

    @property
    def aligned(self) -> bool:
        """Whether the stream ended on a frame boundary.

        A peer that stops mid-frame was either not framing at all or was cut
        off; either way the connection did not end where h2 says it should, and
        a relay that only ever checked the first frame would carry anything at
        all after it.
        """
        return not self._payload and not self._header
