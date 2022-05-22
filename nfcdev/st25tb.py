# SPDX-License-Identifier: GPL-2.0-or-later

"""
Declarations and classes related to ST25TB tags.
"""

from abc import abstractmethod
from enum import IntEnum
from .statem import NFCDevState
from .nfcdev import (
    NFCMessageType,
    NFCTransceiveFlags,
    NFCTransceiveFrameRequestMessage,
)


class ST25TBCommand(IntEnum):
    READ_BLOCK = 0x08
    WRITE_BLOCK = 0x09


class NFCDevStateST25TBReadBlocks(NFCDevState):
    def __init__(self, fsm, blocks):
        super().__init__(fsm)
        self.__data = b""
        self.__blocks = blocks
        fsm.write_message(
            NFCTransceiveFrameRequestMessage(
                bytearray([ST25TBCommand.READ_BLOCK, self.__blocks[0]])
            )
        )

    def process_message(self, header, payload):
        if header.message_type == NFCMessageType.TRANSCEIVE_FRAME_RESPONSE:
            if payload.flags & NFCTransceiveFlags.ERROR:
                return self.failure()
            elif payload.rx_count != 6:
                return self.failure()
            self.__data += payload.data[0:4]
            self.__blocks = self.__blocks[1:]
            if len(self.__blocks) == 0:
                return self.success(self.__data)
            self.fsm.write_message(
                NFCTransceiveFrameRequestMessage(
                    bytes(
                        [
                            ST25TBCommand.READ_BLOCK,
                            self.__blocks[0],
                        ]
                    ),
                )
            )
            return self
        else:
            logging.error(
                "Unexpected packet from RFID device, "
                f"header={header}, payload={payload}"
            )
        return self

    @abstractmethod
    def failure(self):
        """
        Read failed.
        Return the new state.
        """
        pass

    @abstractmethod
    def success(self, data):
        """
        Read succeeded.
        Return the new state.
        """
        pass


class NFCDevStateST25TBWriteBlocks(NFCDevState):
    def __init__(self, fsm, blocks, data):
        super().__init__(fsm)
        self.__data = data
        self.__blocks = blocks
        self._transmit_next_frame()

    def _transmit_next_frame(self):
        if len(self.__blocks) > 0:
            block_data = self.__data[0:4]
            tx_data = bytes([ST25TBCommand.WRITE_BLOCK, self.__blocks[0]]) + block_data
            self.fsm.write_message(
                NFCTransceiveFrameRequestMessage(
                    tx_data,
                    NFCTransceiveFlags.TX_ONLY,
                )
            )
        else:
            # Read system block to make sure the tag is still here.
            self.fsm.write_message(
                NFCTransceiveFrameRequestMessage(bytes([ST25TBCommand.READ_BLOCK, 255]))
            )

    def process_message(self, header, payload):
        if header.message_type == NFCMessageType.TRANSCEIVE_FRAME_RESPONSE:
            if payload.flags & NFCTransceiveFlags.ERROR:
                return self.failure()
            if payload.rx_count == 6 and len(self.__blocks) == 0:
                # All bytes were written, this is the callback from final read
                return self.success()
            if payload.rx_count != 6 and len(self.__blocks) == 0:
                # Final read, but unexpected length
                return self.failure()
            if payload.rx_count != 0:
                # Unexpected payload length for a write
                return self.failure()
            # Write callback.
            self.__blocks = self.__blocks[1:]
            self.__data = self.__data[4:]
            # Write next block or start final read.
            # We should only do this after 7ms
            self.fsm.loop.call_later(0.007, self._transmit_next_frame)
        else:
            logging.error(
                "Unexpected packet from RFID device, "
                f"header={header}, payload={payload}"
            )
        return self

    @abstractmethod
    def failure(self):
        """
        Write failed.
        Return the new state.
        """
        pass

    @abstractmethod
    def success(self):
        """
        Write succeeded.
        Return the new state.
        """
        pass
