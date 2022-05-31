# pynfcdev

Python package to interface with /dev/nfc0 device currently created by
st25r391x Linux driver.

The API is layered:
- `NFCDev` class can be used to directly send and receive message from the
  device. Several classes are used to serialize and unserialize these messages.
- `NFCDevStateMachine` class can be used to interact with the device using a
  state machine approach and an event loop. It is based on `NFCDev`.

Various examples to exhibit the API usage are provided:
- `discover_tags.py` : discover tags with any technology
- `discover_tags_statem.py` : slightly different version using `statem` API
- `st25tb_read_user_data.py` : read ST25TB RFID tags
- `st25tb_read_user_data_statem.py` : different version using `statem` API
- `t2t_read_ndef.py` : read NDEF messages from NFC Type 2 Tags
- `t2t_read_ndef.py` : write NDEF messages from NFC Type 2 Tags
