#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import nfcdev


class ReadUserData(nfcdev.NFCDevStateST25TBReadBlocks):
    def __init__(self, fsm):
        super().__init__(fsm, range(7, 16))

    def failure(self):
        print("Read error (tag removed?)")
        self.fsm.write_message(nfcdev.NFCIdleModeRequestMessage())
        return SelectTag(self.fsm)

    def success(self, data):
        data_str = ":".join("{:02x}".format(c) for c in data)
        print(f"User data: {data_str}")
        self.fsm.write_message(nfcdev.NFCIdleModeRequestMessage())
        return SelectTag(self.fsm)


class ReadSystemBlock(nfcdev.NFCDevStateST25TBReadBlocks):
    def __init__(self, fsm):
        super().__init__(fsm, [255])

    def failure(self):
        print("Read error (tag removed?)")
        self.fsm.write_message(nfcdev.NFCIdleModeRequestMessage())
        return SelectTag(self.fsm)

    def success(self, data):
        data_str = ":".join("{:02x}".format(c) for c in data)
        print(f"System block (255): {data_str}")
        return ReadUserData(self.fsm)


class SelectTag(nfcdev.NFCDevStateDiscover):
    def __init__(self, fsm):
        super().__init__(
            fsm,
            nfcdev.NFCTagProtocol.ST25TB,
            0,
            0,
            0,
            nfcdev.NFCDiscoverFlags.SELECT,
        )

    def process_selected_tag(self, tag_type, tag_info):
        if tag_type == nfcdev.NFCTagType.ST25TB:
            return self.process_st25tb_tag(tag_info)
        return super().process_selected_tag(tag_type, tag_info)

    def process_st25tb_tag(self, tag_info):
        # uid is in little endian
        uid_be = bytearray(tag_info.uid)
        uid_be.reverse()
        uid_str = ":".join("{:02x}".format(c) for c in uid_be)
        print(f"UID: {uid_str}")
        if uid_be[0] != 0xD0:
            print(f"Unexpected MSB, got {uid_be[0]}")
        if uid_be[1] != 0x02:
            print("Not a STMicroelectronics chip, will read block 255 anyway")
        return ReadSystemBlock(self.fsm)


loop = asyncio.get_event_loop()

with nfcdev.NFCDevStateMachine(loop, "/dev/nfc0") as fsm:
    print("Version check: {nfc.check_version()}")
    print("Chip model: {nfc.get_identify_chip_model()}")
    print("Selecting ST25TB tags (exit with control-C)\n")

    try:
        fsm.set_state(SelectTag(fsm))
        loop.run_forever()
    except KeyboardInterrupt:
        pass
