# SPDX-License-Identifier: GPL-2.0-or-later

"""
Declarations and classes related to NFC type 2 tags.
"""

from abc import abstractmethod
from enum import Enum, IntEnum
from typing import Any, Callable, List, Optional, Tuple, Union
import logging

import ndef  # type: ignore

NDEFMessage = Any

from .statem import NFCDevState, NFCDevStateMachine
from .nfcdev import (
    NFCMessageHeader,
    NFCMessageType,
    NFCResponsePayload,
    NFCTransceiveFlags,
    NFCTransceiveFrameRequestMessage,
    NFCTransceiveFrameResponsePayload,
)


class T2TCommand(IntEnum):
    READ_BLOCK = 0x30
    WRITE_BLOCK = 0xA2
    SECTOR_SELECT = 0xC2


class NFCDevStateT2TSelectSector(NFCDevState):
    __SECTOR_SELECT_1 = "sector_select-1"
    __SECTOR_SELECT_2 = "sector_select-2"

    """
    State to select sectors from NFC Type 2 Tags.
    """

    def __init__(
        self,
        fsm: NFCDevStateMachine,
        sector: int,
        success_cb: Callable[[], NFCDevState],
        failure_cb: Callable[[BaseException], NFCDevState],
    ):
        super().__init__(fsm)
        self.__sector = sector
        self.__select_state = None
        self.__success_cb = success_cb
        self.__failure_cb = failure_cb
        fsm.write_message(
            NFCTransceiveFrameRequestMessage(
                bytearray([T2TCommand.SECTOR_SELECT, 0xFF]),
                21000,  # NFC Digital Protocol, A.5, p. 172
                NFCTransceiveFlags.BITS | NFCTransceiveFlags.NOCRC_RX,
            )
        )
        self.__select_state = NFCDevStateT2TSelectSector.__SECTOR_SELECT_1

    def process_message(
        self, header: NFCMessageHeader, payload: Optional[NFCResponsePayload]
    ) -> NFCDevState:
        if header.message_type != NFCMessageType.TRANSCEIVE_FRAME_RESPONSE:
            return self.__failure_cb(ValueError())
        if not isinstance(payload, NFCTransceiveFrameResponsePayload):
            return self.__failure_cb(ValueError())
        if payload.flags & NFCTransceiveFlags.ERROR:
            return self.__failure_cb(OSError())
        if self.__select_state == NFCDevStateT2TSelectSector.__SECTOR_SELECT_1:
            if payload.rx_count != 4:
                return self.__failure_cb(OSError())
            self.fsm.write_message(
                NFCTransceiveFrameRequestMessage(
                    bytearray([self.__sector, 0x00, 0x00]),
                    1000,  # NFC Digital Protocol, A.5, p. 172
                    NFCTransceiveFlags.BITS
                    | NFCTransceiveFlags.NOCRC_RX
                    | NFCTransceiveFlags.TIMEOUT,
                )
            )
            self.__select_state == NFCDevStateT2TSelectSector.__SECTOR_SELECT_2
            return self
        if payload.rx_count != 0:
            return self.__failure_cb(OSError())
        return self.__success_cb()


class NFCDevStateT2TReadBlocks(NFCDevState):
    """
    State to read blocks from NFC Type 2 Tags.
    """

    def __init__(
        self,
        fsm: NFCDevStateMachine,
        start_block: int,
        blocks_count: int,
        current_sector=0,
    ):
        super().__init__(fsm)
        self.__data = b""
        self.__start_block = start_block
        self.__blocks_count = blocks_count
        self.__select_state: Optional[NFCDevStateT2TSelectSector] = None
        self.__selected_sector = current_sector
        self.select_or_read()

    def select_or_read(self) -> NFCDevState:
        start_sector = self.__start_block >> 8
        if start_sector != self.__selected_sector:
            self.__select_state = NFCDevStateT2TSelectSector(
                self.fsm, start_sector, self.select_success, self.failure
            )
            return self
        else:
            return self.select_success()

    def select_success(self) -> NFCDevState:
        self.__selected_sector = self.__start_block >> 8
        self.__select_state = None
        self.fsm.write_message(
            NFCTransceiveFrameRequestMessage(
                bytearray([T2TCommand.READ_BLOCK, self.__start_block & 0xFF]),
                25000,  # NFC Digital Protocol, A.5, p. 172
            )
        )
        return self

    def process_message(
        self, header: NFCMessageHeader, payload: Optional[NFCResponsePayload]
    ) -> NFCDevState:
        if self.__select_state is not None:
            return self.__select_state.process_message(header, payload)
        if header.message_type != NFCMessageType.TRANSCEIVE_FRAME_RESPONSE:
            return self.failure(ValueError())
        if not isinstance(payload, NFCTransceiveFrameResponsePayload):
            return self.failure(ValueError())
        if payload.flags & NFCTransceiveFlags.ERROR:
            return self.failure(OSError())
        if payload.rx_count != 18:
            return self.failure(OSError())
        keep_count = min(4, self.__blocks_count)
        self.__data += payload.data[0 : (4 * keep_count)]
        self.__start_block = self.__start_block + keep_count
        self.__blocks_count = self.__blocks_count - keep_count
        if self.__blocks_count == 0:
            return self.success(self.__data)
        return self.select_or_read()

    @abstractmethod
    def failure(self, ex: BaseException) -> NFCDevState:
        """
        Read failed.
        Return the new state.
        """
        pass

    @abstractmethod
    def success(self, data) -> NFCDevState:
        """
        Read succeeded.
        Return the new state.
        """
        pass


class NFCDevStateT2TWriteBlocks(NFCDevState):
    """
    State to write blocks to NFC Type 2 Tags.
    """

    def __init__(self, fsm: NFCDevStateMachine, start_block, data, current_sector=0):
        super().__init__(fsm)
        self.__data = data
        self.__start_block = start_block
        self.__select_state: Optional[NFCDevStateT2TSelectSector] = None
        self.__selected_sector = current_sector
        self.select_or_write()

    def select_or_write(self) -> NFCDevState:
        start_sector = self.__start_block >> 8
        if start_sector != self.__selected_sector:
            self.__select_state = NFCDevStateT2TSelectSector(
                self.fsm, start_sector, self.select_success, self.failure
            )
            return self
        else:
            return self.select_success()

    def select_success(self) -> NFCDevState:
        self.__selected_sector = self.__start_block >> 8
        self.__select_state = None
        self.fsm.write_message(
            NFCTransceiveFrameRequestMessage(
                bytearray([T2TCommand.WRITE_BLOCK, self.__start_block & 0xFF])
                + self.__data[0:4],
                30000,  # NFC Digital Protocol, A.5, p. 172
                NFCTransceiveFlags.BITS
                | NFCTransceiveFlags.NOCRC_RX
                | NFCTransceiveFlags.NOPAR_RX,
            )
        )
        return self

    def process_message(self, header: NFCMessageHeader, payload) -> NFCDevState:
        if self.__select_state is not None:
            return self.__select_state.process_message(header, payload)
        if header.message_type != NFCMessageType.TRANSCEIVE_FRAME_RESPONSE:
            return self.failure(ValueError())
        if not isinstance(payload, NFCTransceiveFrameResponsePayload):
            return self.failure(ValueError())
        if payload.flags & NFCTransceiveFlags.ERROR:
            return self.failure(OSError())
        if payload.rx_count != 4:
            return self.failure(OSError())
        if payload.data[0] & 0x0F != 0xA:
            return self.failure(OSError())
        self.__data = self.__data[4:]
        self.__start_block = self.__start_block + 1
        if len(self.__data) == 0:
            return self.success()
        return self.select_or_write()

    @abstractmethod
    def failure(self, ex: BaseException) -> NFCDevState:
        """
        Write failed.
        Return the new state.
        """
        pass

    @abstractmethod
    def success(self) -> NFCDevState:
        """
        Write succeeded.
        Return the new state.
        """
        pass


class TLVBlockType(IntEnum):
    NULL = 0x00
    LOCK_CONTROL = 0x01
    MEMORY_CONTROL = 0x02
    NDEF_MESSAGE = 0x03
    PROPRIETARY = 0xFD
    TERMINATOR = 0xFE


class TLVBlock:
    def __init__(self, type: Union[TLVBlockType, int], data: Optional[bytes]):
        self.type = type
        self.data = data

    def __str__(self):
        return f"TLVBlock<type={self.type}, data={self.data}>"

    def __repr__(self):
        return self.__str__()

    def __bytes__(self):
        if self.data:
            data_len = len(self.data)
            if data_len > 254:
                data_len_encoded = bytearray([0xFF, data_len >> 8, data_len & 0xFF])
            else:
                data_len_encoded = bytearray([data_len])
            return bytes([self.type]) + data_len_encoded + self.data
        else:
            return bytes([self.type, 0])

    @classmethod
    def parse(cls, data: bytes) -> Tuple["TLVBlock", bytes]:
        try:
            tlv_type: Union[TLVBlockType, int] = TLVBlockType(data[0])
        except ValueError:
            tlv_type = data[0]
        tlv_length = data[1]
        data_ix = 2
        if tlv_length == 0xFF:
            tlv_length = data[2] << 8 + data[3]
            data_ix = 4
        if tlv_length > 0:
            tlv_data = data[data_ix : (data_ix + tlv_length)]
        else:
            tlv_data = None
        if tlv_type == TLVBlockType.LOCK_CONTROL:
            block: TLVBlock = TLVLockControlBlock(tlv_data)
        elif tlv_type == TLVBlockType.MEMORY_CONTROL:
            block = TLVMemoryControlBlock(tlv_data)
        elif tlv_type == TLVBlockType.NDEF_MESSAGE:
            block = TLVNDEFMessageBlock(tlv_data)
        elif tlv_type == TLVBlockType.TERMINATOR:
            block = TLVTerminatorBlock(tlv_data)
        else:
            block = TLVBlock(tlv_type, tlv_data)
        rest = data[(data_ix + tlv_length) :]
        return block, rest

    @classmethod
    def parse_blocks(cls, data: bytes) -> List["TLVBlock"]:
        blocks = []
        while len(data) > 0:
            block, data = TLVBlock.parse(data)
            blocks.append(block)
            if block.type == TLVBlockType.TERMINATOR:
                break
        return blocks


class TLVLockControlBlock(TLVBlock):
    def __init__(self, data: Optional[bytes]):
        super().__init__(TLVBlockType.LOCK_CONTROL, data)

    def __str__(self) -> str:
        data_hex: Optional[str] = None
        if self.data:
            data_hex = self.data.hex()
        return f"TLVLockControlBlock<data={data_hex}>"


class TLVMemoryControlBlock(TLVBlock):
    def __init__(self, data: Optional[bytes]):
        super().__init__(TLVBlockType.MEMORY_CONTROL, data)

    def __str__(self) -> str:
        data_hex: Optional[str] = None
        if self.data:
            data_hex = self.data.hex()
        return f"TLVMemoryControlBlock<data={data_hex}>"


class TLVNDEFMessageBlock(TLVBlock):
    def __init__(self, arg: Union[bytes, NDEFMessage, None]):
        if arg is None:
            super().__init__(TLVBlockType.NDEF_MESSAGE, None)
            self.ndef: Optional[NDEFMessage] = None
        elif isinstance(arg, bytes):
            super().__init__(TLVBlockType.NDEF_MESSAGE, arg)
            try:
                self.ndef = ndef.NdefMessage(arg)
            except ndef.ndef.InvalidNdefMessage:
                self.ndef = None
        else:
            super().__init__(TLVBlockType.NDEF_MESSAGE, arg.to_buffer())
            self.ndef = arg

    def __str__(self) -> str:
        return f"TLVNDEFMessageBlock<ndef={self.ndef}>"


class TLVTerminatorBlock(TLVBlock):
    def __init__(self, data: Optional[bytes]):
        super().__init__(TLVBlockType.TERMINATOR, data)

    def __str__(self) -> str:
        data_hex: Optional[str] = None
        if self.data:
            data_hex = self.data.hex()
        return f"TLVTerminatorBlock<data={data_hex}>"


class NFCDevStateT2TReadNDEF(NFCDevState):
    """
    State to read NDEF from an NFC Type 2 Tag
    """

    class ReadNDEFDataArea(NFCDevStateT2TReadBlocks):
        def __init__(
            self,
            fsm: NFCDevStateMachine,
            buffer: bytes,
            total_size: int,
            locked: bool,
            success_cb: Callable[[List[NDEFMessage], bool], NFCDevState],
            failure_cb: Callable[[BaseException], NFCDevState],
        ):
            super().__init__(fsm, len(buffer) // 4 + 4, (total_size - len(buffer)) // 4)
            self.__first_blocks = buffer
            self.__locked = locked
            self.__success_cb = success_cb
            self.__failure_cb = failure_cb

        def success(self, data):
            blocks = TLVBlock.parse_blocks(self.__first_blocks + data)
            ndef_messages = [
                block.ndef for block in blocks if isinstance(block, TLVNDEFMessageBlock)
            ]
            if None in ndef_messages:
                return self.__failure_cb(OSError())
            else:
                return self.__success_cb(ndef_messages, self.__locked)

        def failure(self, ex: BaseException):
            return self.__failure_cb(ex)

    class ReadCCBlock(NFCDevStateT2TReadBlocks):
        def __init__(
            self,
            fsm: NFCDevStateMachine,
            success_cb: Callable[[List[NDEFMessage], bool], NFCDevState],
            failure_cb: Callable[[BaseException], NFCDevState],
        ):
            super().__init__(fsm, 3, 4)
            self.__success_cb = success_cb
            self.__failure_cb = failure_cb

        def failure(self, ex: BaseException) -> NFCDevState:
            return self.__failure_cb(ex)

        def success(self, data) -> NFCDevState:
            if data[0] == 0xE1 and data[1] == 0x10 and data[3] in (0x00, 0x0F):
                # NDEF 1.0
                size = data[2] * 8
                return NFCDevStateT2TReadNDEF.ReadNDEFDataArea(
                    self.fsm,
                    data[4:],
                    size,
                    data[3] == 0x0F,
                    self.__success_cb,
                    self.__failure_cb,
                )
            else:
                return self.__failure_cb(OSError())

    def __init__(self, fsm: NFCDevStateMachine):
        super().__init__(fsm)
        self.__initstate = NFCDevStateT2TReadNDEF.ReadCCBlock(
            fsm, self.success, self.failure
        )

    @abstractmethod
    def success(self, messages: List[NDEFMessage], locked: bool) -> NFCDevState:
        """
        Process successfully read NDEF messages.
        """
        pass

    @abstractmethod
    def failure(self, ex: BaseException) -> NFCDevState:
        pass

    def process_message(
        self, header: NFCMessageHeader, payload: Optional[NFCResponsePayload]
    ) -> NFCDevState:
        return self.__initstate.process_message(header, payload)


class NFCDevStateT2TWriteNDEF(NFCDevState):
    """
    State to write NDEF on an NFC Type 2 Tag
    """

    class WriteNDEFDataArea(NFCDevStateT2TWriteBlocks):
        def __init__(
            self,
            fsm: NFCDevStateMachine,
            start_block: int,
            data: bytes,
            success_cb: Callable[[List[NDEFMessage], bool], NFCDevState],
            failure_cb: Callable[[BaseException], NFCDevState],
        ):
            super().__init__(fsm, start_block, data)
            self.__success_cb = success_cb
            self.__failure_cb = failure_cb

        def success(self):
            self.__success_cb()

        def failure(self, ex: BaseException):
            return self.__failure_cb(ex)

    class ReadNDEFDataArea(NFCDevStateT2TReadBlocks):
        def __init__(
            self,
            fsm: NFCDevStateMachine,
            messages: List[NDEFMessage],
            buffer: bytes,
            total_size: int,
            success_cb: Callable[[], NFCDevState],
            failure_cb: Callable[[BaseException], NFCDevState],
        ):
            super().__init__(fsm, len(buffer) // 4 + 4, (total_size - len(buffer)) // 4)
            self.__first_blocks = buffer
            self.__success_cb = success_cb
            self.__failure_cb = failure_cb
            self.__messages = messages

        def success(self, data):
            original_tlv_bin = self.__first_blocks + data
            blocks = TLVBlock.parse_blocks(original_tlv_bin)
            if self.__messages:
                message_blocks = [
                    TLVNDEFMessageBlock(message) for message in self.__messages
                ]
            else:
                message_blocks = [TLVNDEFMessageBlock(None)]
            new_blocks = []
            for block in blocks:
                if isinstance(block, TLVNDEFMessageBlock):
                    new_blocks.extend(message_blocks)
                    message_blocks = []
                    continue
                if isinstance(block, TLVTerminatorBlock):
                    if message_blocks:
                        new_blocks.extend(message_blocks)
                    new_blocks.append(block)
                    break
                new_blocks.append(block)
            new_blocks_bin = b"".join([bytes(block) for block in new_blocks])
            if len(new_blocks_bin) > len(original_tlv_bin):
                return self.__failure_cb(
                    OSError(
                        errno.ENOSPC,
                        f"Cannot write {len(new_blocks_bin)} bytes, max is {len(original_tlv_bin)}",
                    )
                )
            # Pad new_blocks
            if len(new_blocks_bin) < len(original_tlv_bin):
                new_blocks_bin = new_blocks_bin + bytes(
                    len(original_tlv_bin) - len(new_blocks_bin)
                )
            start_block = 4
            while (
                len(new_blocks_bin) > 0 and original_tlv_bin[0:4] == new_blocks_bin[0:4]
            ):
                original_tlv_bin = original_tlv_bin[4:]
                new_blocks_bin = new_blocks_bin[4:]
                start_block += 1
            while (
                len(new_blocks_bin) > 0 and original_tlv_bin[-4:] == new_blocks_bin[-4:]
            ):
                original_tlv_bin = original_tlv_bin[:-4]
                new_blocks_bin = new_blocks_bin[:-4]
            if len(new_blocks_bin) > 0:
                return NFCDevStateT2TWriteNDEF.WriteNDEFDataArea(
                    self.fsm,
                    start_block,
                    new_blocks_bin,
                    self.__success_cb,
                    self.__failure_cb,
                )
            return self.__success_cb()

        def failure(self, ex: BaseException):
            return self.__failure_cb(ex)

    class ReadCCBlock(NFCDevStateT2TReadBlocks):
        def __init__(
            self,
            fsm: NFCDevStateMachine,
            messages: List[NDEFMessage],
            success_cb: Callable[[], NFCDevState],
            failure_cb: Callable[[BaseException], NFCDevState],
        ):
            super().__init__(fsm, 3, 4)
            self.__success_cb = success_cb
            self.__failure_cb = failure_cb
            self.__messages = messages

        def failure(self, ex: BaseException) -> NFCDevState:
            return self.__failure_cb(ex)

        def success(self, data) -> NFCDevState:
            if data[0] == 0xE1 and data[1] == 0x10:
                if data[3] != 0x00:
                    return self.__failure_cb(PermissionError())
                # NDEF 1.0
                size = data[2] * 8
                return NFCDevStateT2TWriteNDEF.ReadNDEFDataArea(
                    self.fsm,
                    self.__messages,
                    data[4:],
                    size,
                    self.__success_cb,
                    self.__failure_cb,
                )
            else:
                return self.__failure_cb(OSError())

    def __init__(self, fsm: NFCDevStateMachine, messages: List[NDEFMessage]):
        super().__init__(fsm)
        self.__initstate = NFCDevStateT2TWriteNDEF.ReadCCBlock(
            fsm, messages, self.success, self.failure
        )

    @abstractmethod
    def success(self) -> NFCDevState:
        """
        NDEF messages were successfully written.
        """
        pass

    @abstractmethod
    def failure(self, ex: BaseException) -> NFCDevState:
        pass

    def process_message(
        self, header: NFCMessageHeader, payload: Optional[NFCResponsePayload]
    ) -> NFCDevState:
        return self.__initstate.process_message(header, payload)
