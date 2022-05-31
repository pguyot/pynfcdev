# SPDX-License-Identifier: GPL-2.0-or-later

import array
import ctypes
import fcntl
import os
import struct
from abc import ABC
from enum import IntEnum, IntFlag
from io import FileIO
from typing import Optional, SupportsBytes, Tuple

from ioctl_opt import IOR  # type: ignore

NFC_RD_GET_PROTOCOL_VERSION = IOR(ord("N"), 0, ctypes.c_uint64)
NFC_PROTOCOL_VERSION_1 = 0x004E464300000001


class NFCMessageType(IntEnum):
    IDENTIFY_REQUEST = 0
    IDENTIFY_RESPONSE = 1
    IDLE_MODE_REQUEST = 2
    IDLE_MODE_ACKNOWLEDGE = 3
    DISCOVER_MODE_REQUEST = 4
    DETECTED_TAG = 5
    SELECT_TAG = 6
    SELECTED_TAG = 7
    TRANSCEIVE_FRAME_REQUEST = 8
    TRANSCEIVE_FRAME_RESPONSE = 9


class NFCTagType(IntEnum):
    ISO14443A = 1
    ISO14443A_T2T = 2
    MIFARE_CLASSIC = 3
    ISO14443A_NFCDEP = 4
    ISO14443A_T4T = 6
    ISO14443A_T4T_NFCDEP = 7
    ISO14443B = 16
    ST25TB = 17
    NFCF = 24

    def is_iso14443a(self):
        return self.value in (
            NFCTagType.ISO14443A,
            NFCTagType.ISO14443A_T2T,
            NFCTagType.MIFARE_CLASSIC,
            NFCTagType.ISO14443A_NFCDEP,
            NFCTagType.ISO14443A_T4T,
            NFCTagType.ISO14443A_T4T_NFCDEP,
        )

    def is_iso14443a4(self):
        return self.value in (
            NFCTagType.ISO14443A_T4T,
            NFCTagType.ISO14443A_T4T_NFCDEP,
        )


class NFCTagProtocol(IntFlag):
    ISO14443A = 1 << NFCTagType.ISO14443A
    ISO14443A_T2T = 1 << NFCTagType.ISO14443A_T2T
    MIFARE_CLASSIC = 1 << NFCTagType.MIFARE_CLASSIC
    ISO14443A_NFCDEP = 1 << NFCTagType.ISO14443A_NFCDEP
    ISO14443A4 = 1 << 5
    ISO14443A_T4T = 1 << NFCTagType.ISO14443A_T4T
    ISO14443A_T4T_NFCDEP = 1 << NFCTagType.ISO14443A_T4T_NFCDEP

    ISO14443B = 1 << NFCTagType.ISO14443B
    ST25TB = 1 << NFCTagType.ST25TB

    NFCF = 1 << NFCTagType.NFCF

    ALL = (
        ISO14443A
        | ISO14443A_T2T
        | MIFARE_CLASSIC
        | ISO14443A_NFCDEP
        | ISO14443A4
        | ISO14443A_T4T
        | ISO14443A_T4T_NFCDEP
        | ISO14443B
        | ST25TB
        | NFCF
    )

    @staticmethod
    def type_to_most_specific_protocol(tag_type):
        return NFCTagProtocol(1 << int(tag_type))

    @staticmethod
    def type_to_most_generic_protocol(tag_type):
        if tag_type.is_iso14443a():
            return NFCTagProtocol.ISO14443A
        else:
            return NFCTagProtocol.type_to_most_specific_protocol(tag_type)


class NFCDiscoverFlags(IntFlag):
    SELECT = 1


class NFCMessageHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("message_type", ctypes.c_uint8),
        ("payload_length", ctypes.c_uint16),
    ]

    def __init__(self, message_type=0, payload_length=0):
        self.message_type = message_type
        self.payload_length = payload_length


class NFCRequestMessage(SupportsBytes):
    pass


class NFCIdentityRequestMessage(NFCRequestMessage):
    def __bytes__(self):
        header = bytes(NFCMessageHeader(NFCMessageType.IDENTIFY_REQUEST, 0))
        return header


class NFCDiscoverModeRequestMessage(NFCRequestMessage):
    class Payload(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("protocols", ctypes.c_uint64),
            ("polling_period", ctypes.c_uint32),
            ("device_count", ctypes.c_uint8),
            ("max_bitrate", ctypes.c_uint8),
            ("flags", ctypes.c_uint8),
        ]

        def __init__(self, protocols, polling_period, device_count, max_bitrate, flags):
            self.protocols = protocols
            self.polling_period = polling_period
            self.device_count = device_count
            self.max_bitrate = max_bitrate
            self.flags = flags

    def __init__(self, protocols, polling_period, device_count, max_bitrate, flags):
        self.payload = NFCDiscoverModeRequestMessage.Payload(
            protocols, polling_period, device_count, max_bitrate, flags
        )

    def __bytes__(self):
        payload = bytes(self.payload)
        header = bytes(
            NFCMessageHeader(NFCMessageType.DISCOVER_MODE_REQUEST, len(payload))
        )
        return header + payload


class NFCIdleModeRequestMessage(NFCRequestMessage):
    def __bytes__(self):
        header = bytes(NFCMessageHeader(NFCMessageType.IDLE_MODE_REQUEST, 0))
        return header


class NFCTagInfoISO14443A:
    def __init__(self, packed):
        self.atqa = struct.unpack("BB", packed[0:2])
        self.sak = packed[2]
        uid_len = packed[3]
        self.uid = packed[4 : 4 + uid_len]

    def tag_id(self):
        return self.uid

    def __str__(self):
        return f"<atqa={self.atqa}, sak={self.sak}, uid={self.uid}>"


class NFCTagInfoISO14443A4(NFCTagInfoISO14443A):
    def __init__(self, packed):
        super().__init__(packed)
        ats_len = packed[14]
        self.ats = packed[15 : 15 + ats_len]

    def __str__(self):
        return f"<atqa={self.atqa}, sak={self.sak}, uid={self.uid}, ats={self.ats}>"


class NFCTagInfoISO14443B:
    def __init__(self, packed):
        self.pupi = packed[0:4]
        self.application_data = packed[4:8]
        self.protocol_info = packed[8:11]

    def tag_id(self):
        return self.pupi

    def __str__(self):
        return (
            f"<pupi={self.pupi}, application_data={self.application_data}, "
            f"protocol_info={self.protocol_info}>"
        )


class NFCTagInfoST25TB:
    def __init__(self, packed):
        self.uid = packed[0:8]

    def tag_id(self):
        return self.uid

    def __str__(self):
        return f"<uid={self.uid}>"


class NFCResponsePayload(ABC):
    pass


class NFCIdentifyResponsePayload(NFCResponsePayload):
    def __init__(self, bytes):
        self.chip_model = bytes


class NFCUnknownResponsePayload(NFCResponsePayload):
    def __init__(self, bytes):
        self.bytes = bytes


class NFCTagInfo(NFCResponsePayload):
    def __init__(self, packed):
        self.tag_type = NFCTagType(packed[0])
        if (
            packed[0] == NFCTagType.ISO14443A
            or packed[0] == NFCTagType.ISO14443A_T2T
            or packed[0] == NFCTagType.MIFARE_CLASSIC
            or packed[0] == NFCTagType.ISO14443A_NFCDEP
        ):
            self.tag_info = NFCTagInfoISO14443A(packed[1:])
        elif (
            packed[0] == NFCTagType.ISO14443A_T4T
            or packed[0] == NFCTagType.ISO14443A_T4T_NFCDEP
        ):
            self.tag_info = NFCTagInfoISO14443A4(packed[1:])
        elif packed[0] == NFCTagType.ISO14443B:
            self.tag_info = NFCTagInfoISO14443B(packed[1:])
        elif packed[0] == NFCTagType.ST25TB:
            self.tag_info = NFCTagInfoST25TB(packed[1:])

    def __str__(self):
        return f"TagInfo<type={self.tag_type}, info={self.tag_info}>"


class NFCSelectTagMessage(NFCRequestMessage):
    def __init__(self, tag_type, tag_uid):
        self.tag_type = tag_type
        self.tag_uid = tag_uid

    def __bytes__(self):
        if self.tag_type.is_iso14443a():
            payload = bytes([self.tag_type, len(self.tag_uid)]) + self.tag_uid
        else:
            payload = bytes([self.tag_type]) + self.tag_uid
        header = bytes(NFCMessageHeader(NFCMessageType.SELECT_TAG, len(payload)))
        return header + payload


class NFCTransceiveFlags(IntFlag):
    # Do not send CRC
    NOCRC_TX = 1 << 0
    NOPAR_TX = 1 << 1
    # TX and RX partial bits, tx_count in bits
    BITS = 1 << 2
    # Do not receive data
    TX_ONLY = 1 << 3
    # Timeout not considered an error (passive ACK)
    TIMEOUT = 1 << 4
    # Do not check CRC on Rx
    NOCRC_RX = 1 << 5
    # Do not decode/expect parity bits on Rx
    NOPAR_RX = 1 << 6
    # Transceive failed, chip is unselected and field is turned off.
    ERROR = 1 << 7


class NFCTransceiveFrameRequestMessage(NFCRequestMessage):
    def __init__(self, data, rx_timeout, flags=0, tx_count=None):
        self.data = data
        self.flags = flags
        self.rx_timeout = rx_timeout
        if tx_count:
            self.tx_count = tx_count
        elif flags & NFCTransceiveFlags.BITS:
            self.tx_count = len(data) * 8
        else:
            self.tx_count = len(data)

    def __bytes__(self):
        payload = (
            struct.pack("=HHB", self.tx_count, self.rx_timeout, int(self.flags))
            + self.data
        )
        header = bytes(
            NFCMessageHeader(NFCMessageType.TRANSCEIVE_FRAME_REQUEST, len(payload))
        )
        return header + payload


class NFCTransceiveFrameResponsePayload(NFCResponsePayload):
    def __init__(self, packed: bytes):
        self.rx_count, self.flags = struct.unpack("=HB", packed[0:3])
        self.data = packed[3:]


class NFCDev:
    """
    Class to interact with /dev/nfc0 device.
    """

    def __init__(self, path="/dev/nfc0"):
        self.path = path

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    def open(self):
        self.fd = os.open("/dev/nfc0", os.O_RDWR)
        self.file = FileIO(self.fd, "rb+")

    def close(self):
        self.file.close()

    def check_version(self):
        b = array.array("Q", [0])
        fcntl.ioctl(self.fd, NFC_RD_GET_PROTOCOL_VERSION, b)
        (version,) = struct.unpack("Q", b)
        return version == NFC_PROTOCOL_VERSION_1

    def get_identify_chip_model(self) -> str:
        self.write_message(NFCIdentityRequestMessage())
        header, payload = self.read_message()
        if header.message_type != NFCMessageType.IDENTIFY_RESPONSE:
            raise ValueError("Unexpected message")
        if not isinstance(payload, NFCIdentifyResponsePayload):
            raise ValueError("Unexpected message")
        return payload.chip_model

    def read_message(
        self,
    ) -> Tuple[NFCMessageHeader, Optional[NFCResponsePayload]]:
        header = NFCMessageHeader()
        self.file.readinto(header)
        payload: Optional[NFCResponsePayload] = None
        if header.payload_length > 0:
            payload_bytes = self.file.read(header.payload_length)
            if header.message_type in (
                NFCMessageType.DETECTED_TAG,
                NFCMessageType.SELECTED_TAG,
            ):
                payload = NFCTagInfo(payload_bytes)
            elif header.message_type == NFCMessageType.TRANSCEIVE_FRAME_RESPONSE:
                payload = NFCTransceiveFrameResponsePayload(payload_bytes)
            elif header.message_type == NFCMessageType.IDENTIFY_RESPONSE:
                payload = NFCIdentifyResponsePayload(payload_bytes)
            else:
                payload = NFCUnknownResponsePayload(payload_bytes)
        return header, payload

    def write_message(self, message):
        self.file.write(bytes(message))
