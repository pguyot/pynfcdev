#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import nfcdev


class ReadNDEF(nfcdev.NFCDevStateT2TReadNDEF):
    def __init__(self, fsm):
        super().__init__(fsm)

    def success(self, messages, locked):
        print("messages:")
        for message in messages:
            print("  message:")
            for record in message.records:
                print("  record:")
                print(f"    tnf: {record.tnf}")
                print(f"    type: {record.type}")
                print(f"    id: {record.id}")
                print(f"    payload: {record.payload}")

        self.fsm.write_message(nfcdev.NFCIdleModeRequestMessage())
        return SelectTag(self.fsm)

    def failure(self, ex: BaseException):
        print(f"Read error (tag removed or not formatted?) {ex}")
        self.fsm.write_message(nfcdev.NFCIdleModeRequestMessage())
        return SelectTag(self.fsm)


class SelectTag(nfcdev.NFCDevStateDiscover):
    def __init__(self, fsm):
        super().__init__(
            fsm,
            nfcdev.NFCTagProtocol.ISO14443A_T2T,
            0,
            0,
            0,
            nfcdev.NFCDiscoverFlags.SELECT,
        )

    def process_selected_tag(self, tag_type, tag_info):
        if tag_type == nfcdev.NFCTagType.ISO14443A_T2T:
            return self.process_t2t_tag(tag_info)
        return super().process_selected_tag(tag_type, tag_info)

    def process_t2t_tag(self, tag_info):
        print(f"ATQA: {tag_info.atqa}")
        print(f"SAK: {tag_info.sak:02x}")
        print(f"UID: {tag_info.uid.hex()}")

        return ReadNDEF(self.fsm)


loop = asyncio.get_event_loop()

with nfcdev.NFCDevStateMachine(loop, "/dev/nfc0") as fsm:
    print("Version check: {nfc.check_version()}")
    print("Chip model: {nfc.get_identify_chip_model()}")
    print("Selecting ISO-14443-A T2T tags (exit with control-C)\n")

    try:
        fsm.set_state(SelectTag(fsm))
        loop.run_forever()
    except KeyboardInterrupt:
        pass
