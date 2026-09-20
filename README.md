# ADShare for PlayStation Portable

> [!IMPORTANT]
> This version of ADShare has been discontinued and is no longer actively maintained.
An improved, modular, and completely rewritten version is now available as ADShare++. You can view and download it [here](https://github.com/welabsdev/PSP-ADShare).

**ADShare** is a PSP homebrew application for direct file sharing between two PlayStation Portable systems using the console's native **Ad Hoc WLAN**.

The project was inspired by **Adhoc File Transfer PSP**, released in 2010. That application proved that direct PSP-to-PSP file transfer was possible, but its interface was very simple and felt almost like a CLI. ADShare revisits the same idea with a more modern, visual, and user-friendly interface.

> Developed by **welabsdev**

---

## Overview

ADShare does not require:

- Internet access
- A router
- An FTP server
- A computer acting as an intermediary

Both PSP systems communicate directly through the PSP's built-in **Ad Hoc networking**.

The application handles console discovery, transfer requests, file acceptance or rejection, transfer progress, hardware information, language selection, and Ad Hoc channel configuration.

---

## Features

- Direct PSP-to-PSP file sharing
- Native PSP Ad Hoc networking
- Automatic discovery of nearby ADShare consoles
- Accept or reject incoming transfers
- File browser for selecting content
- Transfer progress display
- Automatic destination folders
- Support for `ms0:/`
- Support for `ef0:/` on PSP Go
- Ad Hoc channel selection
  - Automatic
  - Channel 1
  - Channel 6
  - Channel 11
- Brazilian Portuguese interface
- English interface
- Runtime language switching
- Real PSP hardware information
- WLAN MAC address display
- Firmware information
- PSP generation detection
- Region/SKU detection through IDStorage
- Tachyon, Baryon, and Pommel hardware information
- Motherboard family/revision detection when enough hardware information is available

---

## File Transfer Protocol

ADShare uses a custom protocol over the PSP Ad Hoc networking stack.

Console discovery and control messages use **PDP**.

The current transfer layer also uses PDP with additional reliability mechanisms implemented by ADShare itself.

A transfer follows a flow similar to:

```text
PSP A                               PSP B
  |                                   |
  |--------- Transfer Request ------->|
  |                                   |
  |<------------ Accept --------------|
  |                                   |
  |----------- HEADER --------------->|
  |<-------- HEADER_ACK --------------|
  |                                   |
  |------ CHUNK #0 + CRC32 ---------->|
  |<---------- ACK #0 ----------------|
  |                                   |
  |------ CHUNK #1 + CRC32 ---------->|
  |<---------- ACK #1 ----------------|
  |                  ...              |
  |------------- FIN ---------------->|
  |<----------- FIN_ACK --------------|
```

The protocol includes:

- Packet sequence numbers
- ACK packets
- Automatic retransmission
- CRC32 validation
- Duplicate packet detection
- Transfer cancellation
- Partial file handling with `.part`

This was designed to improve reliability on real PSP hardware, where packet loss can occur over Ad Hoc WLAN.

---

## Automatic File Destinations

Received files are automatically stored according to their type.

### Photos

```text
ms0:/PICTURE/ADShare/
```

### Music

```text
ms0:/MUSIC/ADShare/
```

### ISO / CSO / ZSO

```text
ms0:/ISO/
```

### PBP

```text
ms0:/PSP/GAME/ADShare/EBOOT.PBP
```

If necessary, ADShare creates another destination folder to avoid overwriting an existing application.

### Other files

```text
ms0:/ADShare/
```

On PSP Go, `ef0:/` can also be used.

---

## Controls

### Start Screen

| Button | Action |
|---|---|
| `START` | Start Ad Hoc |
| `SELECT` | Change Ad Hoc channel |
| `SQUARE` | Switch PT-BR / English |

### Main Screen

| Button | Action |
|---|---|
| `UP / DOWN` | Select another PSP |
| `X` | Select and send a file |
| `R` | Refresh console discovery |
| `SELECT` | Change Ad Hoc channel |
| `TRIANGLE` | Device information |
| `SQUARE` | Switch PT-BR / English |

### Incoming Transfer

| Button | Action |
|---|---|
| `X` | Accept |
| `O` | Reject |

### File Browser

| Button | Action |
|---|---|
| `X` | Open folder / select file |
| `O` | Go back |
| `L` | Switch between `ms0:/` and `ef0:/` when available |

### Transfer Screen

| Button | Action |
|---|---|
| `O` | Cancel transfer |

---

## Ad Hoc Channel

Both PSP systems must use the same Ad Hoc channel.

ADShare supports the channels exposed by the PSP system settings:

```text
Automatic
Channel 1
Channel 6
Channel 11
```

The channel can be changed directly from ADShare using `SELECT`.

---

## Languages

ADShare currently supports:

- Portuguese (Brazil)
- English

The initial interface language follows the PSP system language when possible.

You can switch languages at runtime using:

```text
SQUARE
```

---

## Hardware Information

ADShare can display real hardware information from the PSP.

The application uses:

- KUBridge
- LibPspExploit
- IDStorage
- Tachyon
- Baryon
- Pommel

Information displayed may include:

```text
Model
Generation
Firmware
Region / SKU
System language
WLAN MAC
Ad Hoc channel
IDStorage region
Tachyon
Baryon
Pommel
Motherboard family/revision
```

ADShare does **not** identify the PSP model based on available RAM.

When enough hardware information is available, the application can identify commercial variants such as:

```text
PSP-1000 series
PSP-2000 series
PSP-3000 series
PSP-3001
PSP Go
PSP Street
```

Motherboard revisions are only displayed when the available hardware IDs allow a reasonable identification.

---

## Technical Information

ADShare is written in **C** and built using the PSP homebrew development environment.

Main technologies and libraries:

- PSPSDK
- PSPDEV
- OSLib
- intraFont
- KUBridge
- LibPspExploit
- PSP Ad Hoc networking APIs

The project currently uses a single large source file while the application is still being tested and refined.

A future version may split the project into modules such as:

```text
src/
├── main.c
├── adhoc.c
├── transfer.c
├── protocol.c
├── browser.c
├── hardware.c
├── language.c
└── ui.c
```

---

## Requirements

A PSP capable of running homebrew is required.

For building the project you will need a PSPDEV / PSPSDK environment with the required libraries installed.

Example:

```bash
psp-pacman -Sy psp-cfw-sdk libintrafont
```

You can verify some of the required files with:

```bash
ls /usr/local/pspdev/psp/include/kubridge.h
ls /usr/local/pspdev/psp/include/libpspexploit.h

ls /usr/local/pspdev/psp/lib/libpspkubridge.a
ls /usr/local/pspdev/psp/lib/libpspexploit.a
ls /usr/local/pspdev/psp/lib/libintrafont.a
```

---

## Building

Clone or download the project and run:

```bash
make clean
make
```

A successful build should generate:

```text
ADShare.o
ADShare.elf
PARAM.SFO
EBOOT.PBP
```

Copy the resulting `EBOOT.PBP` to a folder inside:

```text
ms0:/PSP/GAME/
```

For example:

```text
ms0:/PSP/GAME/ADShare/EBOOT.PBP
```

---

## Testing With Two PSPs

Install the **same ADShare build** on both consoles.

Then:

1. Enable the WLAN switch on both PSPs.
2. Open ADShare on both systems.
3. Make sure both use the same Ad Hoc channel.
4. Press `START` on both PSPs.
5. Wait for discovery.
6. Select the other PSP.
7. Press `X`.
8. Choose a file.
9. Accept the transfer on the receiving PSP.

During protocol development, using the same version on both consoles is strongly recommended.

---

## Project Status

ADShare started as an experimental project and grew from a working prototype.

Because of that, the current codebase is not fully modularized yet.

The application is still under active development and some parts of the networking layer may continue to change as more testing is done on real PSP hardware.

Suggestions, bug reports, code improvements, and testing results are welcome.

---

## Credits

### Development

**welabsdev**

### Inspiration

**Adhoc File Transfer PSP**  
Original PSP Ad Hoc file-transfer homebrew released in 2010.

### Tools and Libraries

Thanks to the developers and contributors of:

- PSPSDK
- PSPDEV
- OSLib
- intraFont
- KUBridge
- LibPspExploit
- The PSP homebrew development community

---

## Feedback

If you test ADShare on real PSP hardware, feel free to open an issue or leave a suggestion.

Useful information for bug reports includes:

```text
PSP model:
Firmware / CFW:
ADShare version:
Ad Hoc channel:
Sender model:
Receiver model:
File type:
File size:
Error code:
```

Testing on different PSP revisions is especially helpful for improving compatibility.

---

**ADShare**  
PSP-to-PSP Ad Hoc File Sharing

Developed by **welabsdev**
