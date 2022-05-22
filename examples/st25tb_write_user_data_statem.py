#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import sys

import nfcdev


class WriteTag(nfcdev.NFCDevStateST25TBWriteBlocks):
    def __init__(self, fsm, data):
        super().__init__(fsm, [7, 8, 10], data)

    def failure(self):
        print("Write failed")
        return nfcdev.NFCDevStateDisabled(self.fsm)

    def success(self):
        print("Write succeeded")
        return nfcdev.NFCDevStateDisabled(self.fsm)


class SelectTag(nfcdev.NFCDevStateSelect):
    def __init__(self, fsm, uid, data):
        native_id = bytearray(uid)
        native_id.reverse()
        super().__init__(fsm, nfcdev.NFCTagType.ST25TB, native_id)
        self.__data = data

    def process_selected_tag(self, tag_type, tag_info):
        print("Selected tag, writing it now")
        return WriteTag(self.fsm, self.__data)


if __name__ == "__main__":
    if (
        len(sys.argv) != 2
        and len(sys.argv) != 3
        and (len(sys.argv) == 2 or sys.argv[1] == "--erase")
    ):
        print(f"Syntax: {sys.argv[0]} [--erase] UID")
        print("--erase : write FFs instead of 'hello world!'")
        sys.exit(1)
    erase = len(sys.argv) == 3 and sys.argv[1] == "--erase"
    if erase:
        data = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    else:
        data = b"hello world!"
    try:
        uid = bytes.fromhex(sys.argv[-1].replace(":", ""))
        if len(uid) != 8:
            raise ValueError("Invalid length")
    except ValueError:
        print(f"Invalid UID string. Expected 8 bytes in hex.")
        sys.exit(1)

    loop = asyncio.get_event_loop()

    with nfcdev.NFCDevStateMachine(loop, "/dev/nfc0") as fsm:
        print("Version check: {nfc.check_version()}")
        print("Chip model: {nfc.get_identify_chip_model()}")
        print(f"Selecting ST25TB tag {sys.argv[1]} (exit with control-C)\n")

        try:
            fsm.set_state(SelectTag(fsm, uid, data))
            loop.run_forever()
        except KeyboardInterrupt:
            pass
