# Probe output fixtures

Output of the platform detection probes, used by `detect_test.go`.

| File | Source |
| --- | --- |
| `eos_show_version.txt` | Captured from an Arista DCS-7050CX3 (EOS 4.35.7.2M) |
| `nxos_show_version.txt` | Captured from a Cisco Nexus 3172T (NX-OS 9.3(14)), licence text shortened |
| `junos_show_version.txt` | Captured from a Juniper MX204 (Junos 23.4R2.13), package list shortened |
| `c1200_show_version.txt` | Captured from a Cisco Catalyst 1200 (Cisco Business switch OS 4.1.3.36) |
| `ios_show_version.txt` | Written from the documented Catalyst 3750 (IOS 12.2(55)SE) format; not captured |
| `iosxe_show_version.txt` | Written from the documented Catalyst 9000 (IOS XE 17.9) format; not captured |
| `fortios_get_system_status.txt` | Written from the documented FortiOS 7.4 format; not captured |

Serial numbers, MAC addresses, build IDs and hostnames in captured output are replaced with placeholders. The NX-OS
device name and the JunOS hostname are deliberately set to `Arista-lookalike`, to check that a device-chosen name
cannot satisfy another platform's marker.

The `*_os_release.txt` files are `/etc/os-release` as read by the `cat /etc/os-release` probe. The Cumulus Linux files follow
the published format with the version changed; the Debian 10 and Ubuntu 22.04 files are the stock ones. None are captured.
