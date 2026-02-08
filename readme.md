# Custom Tools Installation

Run `sudo ./install.sh` to install all tools on a new system.

## Files

| File | Install Location | Description |
|------|-----------------|-------------|
| `Linux/VirtualBox/use-vbox.service` | `/etc/systemd/system/` | Systemd service to disable KVM on boot for VirtualBox |
| `Linux/VirtualBox/windows` | `/usr/local/bin/` | Start Win11 VirtualBox VM |
| `Linuxpair-controller.sh` | `/usr/local/bin/pair-controller` | SSH key pairing tool for network controllers |
| `Linux/setMTU.sh` | `/usr/local/bin/setMTU` | Set maximum MTU on eth0 interface |

Run files with `--help` or `-h` for usage instructions.
