# CTAP Bluetooth LE example

[Back to the overview](../../README.md).

Run these commands from the repository root on macOS.

The BLE demo scans for FIDO advertisements during an explicit window, prints
each opaque CoreBluetooth identifier, name, and RSSI, then performs
`authenticatorGetInfo`:

```sh
cd examples/ble
go run . -scan 8s
go run . -scan 8s -id 01234567-89AB-CDEF-0123-456789ABCDEF
```

Use `-id` when multiple candidates are found. A conforming authenticator
protects its FIDO GATT characteristics. The transport relies on macOS to pair
when necessary and establish the encrypted link when those characteristics are
accessed, and waits for the protected GATT operations used during
initialization. Pairing and bond management APIs remain outside this
prototype. macOS may display its pairing prompt on the first run. The terminal
application needs Bluetooth permission; packaged host applications also need
`NSBluetoothAlwaysUsageDescription`.
