#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import sys

import ndef  # type: ignore

import nfcdev


class WriteNDEF(nfcdev.NFCDevStateT2TWriteNDEF):
    def __init__(self, fsm, messages):
        super().__init__(fsm, messages)

    def failure(self, ex: BaseException):
        print(f"Write failed {ex}")
        return nfcdev.NFCDevStateDisabled(self.fsm)

    def success(self):
        print("Write succeeded")
        return nfcdev.NFCDevStateDisabled(self.fsm)


class SelectTag(nfcdev.NFCDevStateSelect):
    def __init__(self, fsm, uid, messages):
        super().__init__(fsm, nfcdev.NFCTagType.ISO14443A_T2T, uid)
        self.__messages = messages

    def process_selected_tag(self, tag_type, tag_info):
        print("Selected tag, writing it now")
        return WriteNDEF(self.fsm, self.__messages)


if __name__ == "__main__":
    if (
        len(sys.argv) != 2
        and len(sys.argv) != 3
        and (len(sys.argv) == 2 or sys.argv[1] == "--erase")
    ):
        print(f"Syntax: {sys.argv[0]} [--erase] UID")
        print("--erase : write no NDEF message instead of 'hello world!'")
        sys.exit(1)
    erase = len(sys.argv) == 3 and sys.argv[1] == "--erase"
    if erase:
        messages = []
    else:
        text_record = (
            ndef.TNF_WELL_KNOWN,
            ndef.RTD_TEXT,
            b"id",
            b"hello world",
        )
        text_message = ndef.new_message(text_record)
        messages = [text_message]
    try:
        uid = bytes.fromhex(sys.argv[-1].replace(":", ""))
        if len(uid) not in (4, 7, 10):
            raise ValueError("Invalid length")
    except ValueError:
        print("Invalid UID string. Expected 4, 7 or 10 bytes in hex.")
        sys.exit(1)

    loop = asyncio.get_event_loop()

    with nfcdev.NFCDevStateMachine(loop, "/dev/nfc0") as fsm:
        print("Version check: {nfc.check_version()}")
        print("Chip model: {nfc.get_identify_chip_model()}")
        print(f"Selecting ISO-14443-A T2T {sys.argv[1]} (exit with control-C)\n")

        try:
            fsm.set_state(SelectTag(fsm, uid, messages))
            loop.run_forever()
        except KeyboardInterrupt:
            pass
