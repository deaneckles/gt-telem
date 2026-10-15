"""
Parse real GT7 datagrams through TurismoClient.

The datagrams below were captured from a PlayStation 5 running Gran Turismo 7
and are stored encrypted, exactly as received on UDP port 33740, so these tests
exercise decryption and parsing together.

Measured datagram sizes (4-byte "0S7G" header included):
  "A" = 296 bytes, "B" = 316 bytes, "~" = 344 bytes.
"B" appends the 5-float motion block at offset 0x128. "~" appends that same
motion block at 0x128 and then its own 28-byte block at 0x13C (filtered
throttle, filtered brake, 2 unknown bytes, a 4-float vector, energy recovery,
1 unknown float).
"""

import base64
import math
import struct
import unittest
from unittest import mock

from gt_telem.models.helpers import SpanReader
from gt_telem.turismo_client import TurismoClient

HEADER_LEN = 4  # "0S7G"
MOTION_OFFSET = 0x128  # offsets are from the start of the datagram
TILDE_OFFSET = 0x13C
PACKET_SIZE = {"A": 296, "B": 316, "~": 344}

# Real datagrams, base64 of the encrypted bytes exactly as received.

# Heartbeat "~" (344 bytes): driving, throttle moving, brake not applied.
TILDE_453340 = (
    "asUtAVWWNahwlveXEQb/+bXBkqJxupeXZUd8INVNYvfsz0GIjfZacBZWjl/pcosenNto1ME/+DWubcbqmupE"
    "PV1C5er0BV9PBQUcH/9FGDrjH6+pHgirrriEPvpx7ISELpZgUAuGsc2IY/2MlisHdzA2Ojf32x83cE95/OER"
    "fNcKxfePvypVv+OAcqo9FoJ5vjoqoRvj1LvoK/+I/+kdQIaN8Y6xayfmX35c773N9YHxzDjPiYhEJodvKjcE"
    "45WdhPvqe0FH7Ucm+TbSxOfN45yMdWGN8gusLy+HWywmzINk+KBK8Q6qntMy0OgHpNl1BBx3UKeSf0ET7Gd4"
    "WadPv6WDXEhB6LUp8RsQvVVFTs7Kh9l1kXniTKv0/uVP0TgtPTK7uNTfotvvwiX5dKaDt1C4f42eQF2L+/nb"
    "GCmm5tkNqUpbc+c0GzYJ0gEv+RqUyCbiwo4haNY="
)

TILDE_453360 = (
    "YaGodllbBvh6Umey7q9z3J7GL1kh5WZ7yleJReIGeUb17Jtc7DUYhhztaLs4cbIjhVI06mxQggWoopuu+Pp/"
    "HfGagIGpA2Ifg/3odxXqGmGK0XbSqsxOGd2kuT2kgOcbh5ni+khc9SCzGLD9y7sCEcH3GrzWV3ML7+dTcUxO"
    "40vANVd+JZ6eVDvhc/c1mTPZ4QIrKfpjiuYrn9FZG75A09XGSaOaWeLDF6hRTaiqJEnBkI/s8PwYMNPIQpph"
    "1jGRVGxlNK8g7R6f9pjAryT3p3CW2L7yNJoUHroaxwoZeWi54M7bJIdQZ8nMhV/yup5wH5W/ToBQ+ttl7IZ1"
    "GmGVknfg5Eg6nyiACV8IcO5P0n878exX4sFP5Owh/5RDfLaCQcy5l5TZluNY3DnIsVNrY58ZjmcVRlcLQx9G"
    "QCc7aajxYgfcgGCNSJ0XlUe625/dilf4TLR9bM0="
)

TILDE_453480 = (
    "jim+AaS05FG7dxg9Rt2VnFE5nSS99qFj+1VDChO6YJ2OJ4+DNAEdbOvz+mZzo/CbFmAXMJs7ewUjfMNEC5Dc"
    "n3+h4VBePiclfoGlggtKSldPbb/CQ3h/TvQh7GJreParu2OTgyT5rvara48kRlFU03xXkh8fknRCOXXsuxaK"
    "sCexVGhB/XN8KhwNdXjxv1XHcjN5RwMW6qJTjJYwlxQZ6/qIS3DXeKsB7iUrnVw/x6CycBu3TPqTlmWRV9Dj"
    "odanoOfsQwtFaJCQ2F0icSFTCpHqTR290HF8NHFthCwlLzCzFw+CNpUuPdIGbpRl0a7lmfU+3IzaS7i0Era3"
    "3M+OUMxFbrnDn0LWpN7gvhc7HrydnNuobMTcG6EsFXD5TcMGuGqkmrjwWtsc4py9Ar4sOigfhjIYrxIXMzfT"
    "Vvgbwf+68wmK7oXtORfHJPzVvOrf3SIPm5cNft8="
)

TILDE_453630 = (
    "cUlF9dsgGFVEiVsQkUsBHQS04Aa0E9ncVC5fYFGqQKyk+GcLALiKEK9Z97G7yOLOTFBa0LrnFUotJ3TDZBV4"
    "I7idSbD2M8FaIGUtw3DVFYJL1dZu2I9MEfkQWYTEET3phBPZpA7i5A9qqCxBgeAfqH6RI3FPNtA44QwvC1n8"
    "ZeXYo6/lGGJVq2NePGoe0aGj9zBQ85dodNxQ7S04usUSPziI87lSRxyo4yaGY2grDJG06DmpG7SphD1OUC3w"
    "RPROaTukHF066884quM68mrAuVRwWiUjbzlLI6WQXtoOZvBL9KIfsZ2u8+vXDlI/wa7uTTYndfg9cpF/a71M"
    "WoZHhWkVvwWZtqxU5zdLYD2TLdZ0rrEeexOqWp+TwQcaE8iz1e55hz248h/Pcjx6fbJ8UtP+eQfR7/IgdClL"
    "zJsCMPpxh80+lPouV0DI5ysZ53fo2dShjLaB/AU="
)

# Heartbeat "B" (316 bytes): car idle on track.
B_443673 = (
    "WrLEDrUp62rjjpa4cfhnRyaOyTWVwX4VLwkggSPyH4N2VytYIlnmRwoTr6squA7RfGgwD3WI5W4euKcW8JUd"
    "8qFPzu1dStsKg10TJMAgn8kcW8/KYjBkkE2mQ/L14INER+gmo4iL+i/TdmSkGpuem1rx1178sPF7z8uLh7zG"
    "bjBA5VcrjgQ175kUJ8t1W57nDDTfPFEIVBOl0RKauP9is3qsgG5tagvAdof3Vq4MG/L+mDfrefNRGhwFMFXI"
    "nOLs8nF48C+AjlKo65bJNgOS0eISpavDJ2Ay+Ds1Hk8bwOcxk91DYD+ewda+gypVmTz3segicJCCcjo6uFfR"
    "wOxSAOi7QqbkLkHexGn/e/uM10NznSojZZcmtXIVzWi+K3Bsr+rUKAV/c7AX7u7+Qy9NODl56WckmXyW3enV"
    "PQ=="
)

# Heartbeat "A" (296 bytes): driving.
A_380561 = (
    "Kr+PeN5BF1tFFSVtjrh+C97ORGPxN+gWnc26iflOlo3l7Pjn35SmUA9DzvuLe0YOiyiJo/Bj4/BjlxWYNJGS"
    "YVUV2FtrVNkER/b7WGaSywD3hLeA1c07QK7elJjXbMev0cR1Em9lVFAFq5cktwXcEm9LtAw0GxXMJ8Q5QMp/"
    "wq3dVS7/RmHQkeEGj5gxBYQC1ZrqDKH1j0vM3nrfQkSKslEDS2mbEVWMdGqs02OyrP1/KUdQxA5LnLa+O28I"
    "tKcikdB7Gkn4KLJw0Zehh8m8mEU4uZBd96SURSfgyM9AOvISwtoBuBdZKVIhTqSmM1rfRJk7kL5Q7G+9ekjx"
    "j9PVAkYbty6ofLYFmilZS/r0QViLQG1G/63MsTM+nEwAY05RkhLIxk+fUKk="
)

# (packet_id, throttle, brake, datagram)
TILDE_DATAGRAMS = [
    (453340, 96, 0, TILDE_453340),
    (453360, 208, 0, TILDE_453360),
    (453480, 50, 0, TILDE_453480),
    (453630, 0, 0, TILDE_453630),
]
B_DATAGRAM = (443673, 0, 0, B_443673)
A_DATAGRAM = (380561, 245, 0, A_380561)


def make_client(heartbeat_type):
    # Skip PlayStation discovery; nothing is sent or received in these tests.
    with mock.patch(
        "gt_telem.turismo_client.get_ps_ip_type", return_value=("192.0.2.1", "PS5")
    ):
        return TurismoClient(is_gt7=True, heartbeat_type=heartbeat_type)


class TestParseRealDatagrams(unittest.TestCase):
    def setUp(self):
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client._callback_executor.shutdown(wait=False)

    def client(self, heartbeat_type):
        client = make_client(heartbeat_type)
        self.clients.append(client)
        return client

    def parse(self, client, datagram):
        packet_id, throttle, brake, b64 = datagram
        raw = base64.b64decode(b64)
        self.assertEqual(len(raw), PACKET_SIZE[client.heartbeat_type])
        client._handle_data(raw)
        telemetry = client.telemetry
        self.assertIsNotNone(telemetry, "datagram was not decrypted and parsed")
        self.assertEqual(
            (telemetry.packet_id, telemetry.throttle, telemetry.brake),
            (packet_id, throttle, brake),
        )
        plaintext = client._crypto.decrypt(raw)
        self.assertEqual(plaintext[:HEADER_LEN], b"0S7G")
        return telemetry, plaintext

    def motion_block(self, plaintext):
        return struct.unpack_from("<5f", plaintext, MOTION_OFFSET)

    def test_tilde_filtered_pedals_match_pedals(self):
        client = self.client("~")
        for datagram in TILDE_DATAGRAMS:
            telemetry, _ = self.parse(client, datagram)
            self.assertEqual(telemetry.throttle_filtered, telemetry.throttle)
            self.assertEqual(telemetry.brake_filtered, telemetry.brake)
            self.assertEqual((telemetry.unk_tilde_1, telemetry.unk_tilde_2), (0, 0))
            self.assertEqual(telemetry.energy_recovery, 0.0)  # car without recovery
            self.assertIsNotNone(telemetry.extended_data)
        # The throttle moves across these packets, so the comparison is informative.
        self.assertGreater(len({d[1] for d in TILDE_DATAGRAMS}), 1)

    def test_tilde_carries_the_motion_block_before_the_extended_block(self):
        client = self.client("~")
        for datagram in TILDE_DATAGRAMS:
            telemetry, plaintext = self.parse(client, datagram)
            motion = (
                telemetry.wheel_rotation_radians,
                telemetry.filler_float_fb,
                telemetry.sway,
                telemetry.heave,
                telemetry.surge,
            )
            self.assertEqual(motion, self.motion_block(plaintext))
            self.assertLessEqual(abs(telemetry.wheel_rotation_radians), math.pi)
            self.assertIsNotNone(telemetry.motion_data)
            filtered = struct.unpack_from("<BB", plaintext, TILDE_OFFSET)
            self.assertEqual(
                (telemetry.throttle_filtered, telemetry.brake_filtered), filtered
            )

    def test_b_has_motion_data_but_no_extended_data(self):
        client = self.client("B")
        telemetry, plaintext = self.parse(client, B_DATAGRAM)
        motion = (
            telemetry.wheel_rotation_radians,
            telemetry.filler_float_fb,
            telemetry.sway,
            telemetry.heave,
            telemetry.surge,
        )
        self.assertEqual(motion, self.motion_block(plaintext))
        self.assertIsNotNone(telemetry.motion_data)
        self.assertIsNone(telemetry.extended_data)
        self.assertIsNone(telemetry.throttle_filtered)

    def test_a_has_neither_motion_nor_extended_data(self):
        client = self.client("A")
        telemetry, _ = self.parse(client, A_DATAGRAM)
        self.assertIsNone(telemetry.motion_data)
        self.assertIsNone(telemetry.extended_data)
        self.assertIsNone(telemetry.wheel_rotation_radians)

    def test_each_heartbeat_type_consumes_its_whole_packet(self):
        for heartbeat_type, datagram in (
            ("A", A_DATAGRAM),
            ("B", B_DATAGRAM),
            ("~", TILDE_DATAGRAMS[0]),
        ):
            client = self.client(heartbeat_type)
            raw = base64.b64decode(datagram[3])
            plaintext = client._crypto.decrypt(raw)
            reader = SpanReader(plaintext[HEADER_LEN:], "little")
            client._parse_telemetry(reader)
            self.assertEqual(reader.position, len(raw) - HEADER_LEN, heartbeat_type)


if __name__ == "__main__":
    unittest.main()
