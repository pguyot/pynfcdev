# SPDX-License-Identifier: GPL-2.0-or-later

"""
State machine to operate nfc device.
"""

import logging
from abc import ABC, abstractmethod
from enum import Enum

from .nfcdev import (
    NFCDev,
    NFCDiscoverModeRequestMessage,
    NFCIdleModeRequestMessage,
    NFCMessageHeader,
    NFCMessageType,
    NFCSelectTagMessage,
    NFCTagProtocol,
    NFCTransceiveFrameRequestMessage,
)


class NFCDeviceState(Enum):
    IDLE = "idle"
    DISCOVER = "discover"
    SELECT = "select"
    SELECTED = "selected"
    TRANSCEIVE_FRAME = "transceive_frame"


class NFCDevState(ABC):
    def __init__(self, fsm: "NFCDevStateMachine"):
        self.fsm = fsm

    @abstractmethod
    def process_message(self, header, payload) -> "NFCDevState":
        """
        Process a message.
        Return the new state (can be self)
        """
        pass


class NFCDevStateDisabled(NFCDevState):
    def process_message(self, header, payload) -> NFCDevState:
        if header.message_type != NFCMessageType.IDLE_MODE_ACKNOWLEDGE:
            logging.error(
                "Unexpected packet from RFID device, "
                f"header={header}, payload={payload}"
            )
        return self


class NFCDevStateDiscover(NFCDevState):
    def __init__(
        self,
        fsm: "NFCDevStateMachine",
        protocols,
        polling_period,
        device_count,
        max_bitrate,
        flags,
    ):
        super().__init__(fsm)
        self.__protocols = protocols
        self.__polling_period = polling_period
        self.__device_count = device_count
        self.__max_bitrate = max_bitrate
        self.__flags = flags
        if self.fsm.get_device_state() == NFCDeviceState.IDLE:
            self.enter_from_idle()

    def enter_from_idle(self) -> NFCDevState:
        self.fsm.write_message(
            NFCDiscoverModeRequestMessage(
                self.__protocols,
                self.__polling_period,
                self.__device_count,
                self.__max_bitrate,
                self.__flags,
            )
        )
        return self

    def process_message(self, header, payload) -> NFCDevState:
        if header.message_type == NFCMessageType.IDLE_MODE_ACKNOWLEDGE:
            return self.enter_from_idle()
        if header.message_type == NFCMessageType.SELECTED_TAG:
            return self.process_selected_tag(payload.tag_type, payload.tag_info)
        if header.message_type == NFCMessageType.DETECTED_TAG:
            return self.process_detected_tag(payload.tag_type, payload.tag_info)
        logging.error(
            "Unexpected packet from RFID device, " f"header={header}, payload={payload}"
        )
        return self

    def process_selected_tag(self, tag_type, tag_info) -> NFCDevState:
        """
        Process selected tag.
        By default unselect it by turning field off and returning to idle mode
        """
        self.fsm.write_message(NFCIdleModeRequestMessage())
        return self

    def process_detected_tag(self, tag_type, tag_info) -> NFCDevState:
        return self


class NFCDevStateDetectRemoval(NFCDevState):
    REMOVED_TIMEOUT = 1.5

    def __init__(self, fsm: "NFCDevStateMachine", tag_type, tag_info, polling_period):
        super().__init__(fsm)
        self.__tag_type = tag_type
        self.__tag_id = tag_info.tag_id()
        self.__polling_period = polling_period
        self.__polling_timerhandle = None
        if self.fsm.get_device_state() == NFCDeviceState.IDLE:
            self.enter_from_idle()

    def _start_timer(self):
        self.__polling_timerhandle = self.fsm.loop.call_later(
            NFCDevStateDetectRemoval.REMOVED_TIMEOUT, self._timer_cb
        )

    def _cancel_timer(self):
        if self.__polling_timerhandle:
            self.__polling_timerhandle.cancel()
            self.__polling_timerhandle = None

    def _timer_cb(self):
        self.fsm.set_state(self.process_removed_tag(self.__tag_type, self.__tag_id))

    def enter_from_idle(self) -> NFCDevState:
        """
        Only listen to current tag's protocol
        """
        protocol = NFCTagProtocol.type_to_most_specific_protocol(self.__tag_type)
        self.fsm.write_message(
            NFCDiscoverModeRequestMessage(
                protocol,
                self.__polling_period,
                1,
                0,
                0,
            )
        )
        self._start_timer()
        return self

    def process_message(self, header, payload) -> NFCDevState:
        if header.message_type == NFCMessageType.IDLE_MODE_ACKNOWLEDGE:
            return self.enter_from_idle()
        if header.message_type == NFCMessageType.DETECTED_TAG:
            self._cancel_timer()
            if payload.tag_info.tag_id() == self.__tag_id:
                self._start_timer()
                return self
            return self.process_detected_tag(payload.tag_type, payload.tag_info)
        logging.error(
            "Unexpected packet from RFID device, " f"header={header}, payload={payload}"
        )
        return self

    @abstractmethod
    def process_removed_tag(self, tag_type, tag_id) -> NFCDevState:
        pass

    def process_detected_tag(self, tag_type, tag_info) -> NFCDevState:
        """
        Another tag was detected.
        By default, call process_removed_tag (and ignore the new tag)
        """
        return self.process_removed_tag(self.__tag_type, self.__tag_id)


class NFCDevStateSelect(NFCDevState):
    def __init__(self, fsm: "NFCDevStateMachine", tag_type, tag_id):
        super().__init__(fsm)
        self.__tag_type = tag_type
        self.__tag_id = tag_id

        if self.fsm.get_device_state() == NFCDeviceState.IDLE:
            self.enter_from_idle()

    def enter_from_idle(self) -> NFCDevState:
        self.fsm.write_message(
            NFCSelectTagMessage(
                self.__tag_type,
                self.__tag_id,
            )
        )
        return self

    def process_message(self, header: NFCMessageHeader, payload):
        if header.message_type == NFCMessageType.IDLE_MODE_ACKNOWLEDGE:
            return self.enter_from_idle()
        if header.message_type == NFCMessageType.SELECTED_TAG:
            return self.process_selected_tag(payload.tag_type, payload.tag_info)
        logging.error(
            "Unexpected packet from RFID device, " f"header={header}, payload={payload}"
        )
        return self

    def process_selected_tag(self, tag_type, tag_info) -> NFCDevState:
        """
        Process selected tag.
        By default unselect it by turning field off and returning to idle mode
        """
        self.fsm.write_message(NFCIdleModeRequestMessage())
        return self


class NFCDevStateMachine:
    """
    Class to handle an nfc device with an event loop.
    """

    def __init__(self, loop, path="/dev/nfc0"):
        self.__dev = NFCDev(path)
        self.loop = loop

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    def open(self):
        self.__dev.open()
        if not self.__dev.check_version():
            raise IOError("Incompatible version")
        self.loop.add_reader(self.__dev.fd, self._read_from_device)
        self.__state = NFCDevStateDisabled(self)
        self.__device_state = NFCDeviceState.IDLE

    def close(self):
        self.__dev.close()

    def get_device_state(self):
        return self.__device_state

    def set_state(self, new_state):
        self.__state = new_state

    def write_message(self, message):
        """
        Write a message to the device.
        Called from state handlers
        Mirrors the device state
        """
        if message.__class__ == NFCDiscoverModeRequestMessage:
            self.__device_state = NFCDeviceState.DISCOVER
        elif message.__class__ == NFCSelectTagMessage:
            self.__device_state = NFCDeviceState.SELECT
        elif message.__class__ == NFCTransceiveFrameRequestMessage:
            self.__device_state = NFCDeviceState.TRANSCEIVE_FRAME
        self.__dev.write_message(message)

    def _read_from_device(self):
        """
        Read callback.
        """
        header, payload = self.__dev.read_message()
        if header.message_type == NFCMessageType.SELECTED_TAG:
            self.__device_state = NFCDeviceState.SELECTED
        elif header.message_type == NFCMessageType.TRANSCEIVE_FRAME_RESPONSE:
            self.__device_state = NFCDeviceState.SELECTED
        elif header.message_type == NFCMessageType.IDLE_MODE_ACKNOWLEDGE:
            self.__device_state = NFCDeviceState.IDLE
        self.__state = self.__state.process_message(header, payload)
