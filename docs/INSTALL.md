# installing airscope

Two levels of install: the **default build** and the **live-capture
build**. The default build is what `cargo build` gives you with zero
configuration — enough to run the TUI, parse pcap files, and craft
frames. The live-capture build adds the ability to read packets off
a real radio and inject them. That one needs a platform-specific
packet-capture library.

---

## 0. prerequisites on every platform

- **Rust 1.85 or newer**: install via [rustup](https://rustup.rs).
- **git** to clone the repository.
- **A terminal emulator** that speaks 256-colour and unicode. Windows
  Terminal, iTerm2, Alacritty, kitty, konsole, gnome-terminal are all
  fine; the old `cmd.exe` works but the banner looks less impressive.

Clone and run the default build once to make sure the baseline works:

```bash
git clone https://github.com/aykutsp/airscope.git
cd airscope
cargo build --release
./target/release/airodump --list-interfaces
./target/release/airview samples/demo-01.pcap
```

If those two commands succeed you can already use ~70% of the suite.
Everything below only applies if you want **live capture** on a real
radio.

---

## 1. linux

```bash
# distribution package
sudo apt install libpcap-dev              # debian / ubuntu / mint
sudo dnf install libpcap-devel            # fedora / rhel / rocky
sudo pacman -S libpcap                    # arch
sudo zypper install libpcap-devel         # opensuse

# build with live capture enabled for every tool that needs it
cargo build --release --features "\
  airscope-airodump/live \
  airscope-airmon/live \
  airscope-aireplay/live \
  airscope-airbase/live"
```

Then you'll need a wireless card with a driver that supports monitor
mode. Most Intel / Ralink / Atheros cards do; some Realtek cards need
an out-of-tree driver. Put the card into monitor mode with:

```bash
sudo ./target/release/airmon start wlan0
sudo ./target/release/airodump -i wlan0
```

### capabilities instead of `sudo`

If you don't want to run as root every time:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/airodump
```

That grants the specific binary the two capabilities it needs; no
other process on the system is affected.

---

## 2. macos

```bash
brew install libpcap
cargo build --release --features "\
  airscope-airodump/live \
  airscope-aireplay/live \
  airscope-airbase/live"
```

Monitor mode on macOS is unusual: Apple's driver stack only exposes
it through **Wireless Diagnostics → Sniffer** (hold Option while
clicking the Wi-Fi menu bar icon). Start a sniffer session there on
the channel you care about, then point airodump at the resulting
interface. `airmon start` is not implemented on macOS on purpose —
Apple's driver takes care of the mode switch and shelling out to
`tcpdump` just creates confusion.

Some USB adapters with Realtek / Atheros chipsets ship with their
own kext that exposes a proper monitor-mode interface; those work
directly with `airodump -i <iface>`.

---

## 3. windows

Windows is the fiddliest of the three because of how library linking
works. It's still a one-time setup — about five minutes.

### 3.1 install Npcap runtime (required)

1. Download the Npcap installer from <https://npcap.com>.
2. Run it. Enable **"install Npcap in WinPcap API-compatible mode"**
   during the wizard. This drops `wpcap.dll` / `packet.dll` into
   `C:\Windows\System32\Npcap\` where the Rust `pcap` crate can find
   them at runtime.
3. Reboot if the installer asks.

Without this step, `airodump -i Wi-Fi` will compile but fail at
runtime because the DLL isn't present.

### 3.2 install Npcap SDK (required to compile with `--features live`)

1. Download `npcap-sdk-*.zip` from <https://npcap.com/#download>
   (not the installer, the SDK zip).
2. Extract it somewhere without spaces in the path — for example
   `C:\npcap-sdk`. Paths with spaces work but add friction with
   mingw's linker.

### 3.3 pick your toolchain

`rustup` gives you one of two Windows toolchains. The live-capture
build recipe is different for each.

#### 3.3.1 MSVC toolchain (recommended)

This is the default when you install rustup on Windows and already
have Visual Studio / Build Tools installed.

```powershell
# from the repo root, in PowerShell
$env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
cargo build --release --features "airscope-airodump/live airscope-aireplay/live airscope-airbase/live"
```

That's it. MSVC can link `wpcap.lib` straight out of the SDK with no
renaming.

#### 3.3.2 mingw toolchain (x86_64-pc-windows-gnu)

mingw's `ld` looks for `libwpcap.a`, not `wpcap.lib`. Fortunately the
two formats are compatible — you just need to rename:

```bash
# in git-bash / msys2
cd /c/npcap-sdk/Lib/x64
cp wpcap.lib libwpcap.a
cp Packet.lib libPacket.a
```

Then tell cargo where to find the library. The cleanest way is a
project-local `.cargo/config.toml`:

```toml
# airscope/.cargo/config.toml
[target.x86_64-pc-windows-gnu]
rustflags = ["-L", "C:/npcap-sdk/Lib/x64"]
```

Now rebuild:

```bash
cargo build --release --features "airscope-airodump/live airscope-aireplay/live airscope-airbase/live"
```

### 3.4 after the build — and the managed-mode trap

```powershell
.\target\release\airodump.exe --list-interfaces
.\target\release\airodump.exe -i "Wi-Fi"
```

`--list-interfaces` will show Npcap's raw device names
(`\Device\NPF_{GUID}`). Pass any of those to `-i`, **or** pass a
friendly name like `"Wi-Fi"` — airodump will fuzzy-match it against
pcap's description strings and auto-resolve. That's why the resolved
name is printed on the first line of the capture output.

**Important expectation check.** The moment you start a live capture
on a Windows Wi-Fi adapter, airodump prints this warning:

```
airodump: linktype = Ethernet.

this means the capture backend handed us already-decoded
Ethernet frames instead of raw 802.11. that happens when
the interface is in MANAGED mode — the driver strips the
802.11 headers before pcap sees them.
```

That warning is not a bug. It is the **default behaviour of every
consumer Wi-Fi driver on Windows**: Microsoft's NDIS stack tears the
802.11 header off every frame and presents an Ethernet-shaped fake
interface to user-space. Wireshark sees exactly the same thing, for
the same reason. There is nothing the scanner can do to recover
beacons / probes / deauth from an Ethernet-framed capture — the
information has already been discarded upstream.

You have three options, in increasing order of effort:

1. **Accept the Ethernet view.** `airview` and `airodump` will
   happily parse unicast data frames aimed at your own MAC. That's
   enough to observe your own network load, test the BPF filter,
   and verify the whole stack is alive.
2. **Use a second adapter with a proper monitor-mode driver.** USB
   adapters built around the Atheros AR9271, Ralink RT3572, or
   Realtek 8812AU chipsets can be switched to monitor mode on
   Windows by re-flashing them to the libpcap-friendly driver
   variant via **Zadig**. Once done, Npcap reports `LINKTYPE_IEEE802_11_RADIOTAP`
   and airodump behaves identically to Linux.
3. **Run the live scan on Linux.** Boot a Linux VM or live USB,
   `sudo apt install libpcap-dev`, build with `--features live`,
   `sudo airmon start wlan0`, done. This is the reference
   environment; everything is verified against it.

If you only want to read pcap files on Windows — no live capture —
**skip all of section 3**. The default build is all you need.

---

## 4. troubleshooting

### `cannot find -lwpcap`

MinGW linker can't locate the Npcap SDK. Make sure you:

- extracted the SDK to a path without unusual characters
- renamed `wpcap.lib` → `libwpcap.a` (mingw only)
- pointed rustflags at the `Lib/x64` folder

Run `cargo clean` then retry.

### `error: failed to run custom build command for pcap`

Linux: you're missing `libpcap-dev` or the equivalent `-devel`
package. macOS: `brew install libpcap`. Windows: see section 3.2.

### `the pcap library could not be loaded`

Runtime DLL is missing. Linux: reinstall `libpcap0.8`. Windows:
reinstall the Npcap runtime (section 3.1) and make sure you ticked
the WinPcap compatibility checkbox.

### `no such device: wlan0`

The interface name is wrong for your machine. Find yours with

```bash
./target/release/airodump --list-interfaces
```

or on Linux:

```bash
ip link
```

### `Operation not permitted`

Linux: live capture and injection need `CAP_NET_RAW` + `CAP_NET_ADMIN`.
Run under `sudo` or use the `setcap` recipe in section 1.

### `airmon start` fails with "rfkill: WLAN hard blocked"

Linux: your hardware kill switch (or systemd-rfkill) has blocked
the radio. `sudo rfkill unblock wifi` fixes it.

---

## 5. minimum toolchain matrix

| OS          | Rustc | Build tools                    | Live capture lib              |
|-------------|:-----:|--------------------------------|-------------------------------|
| Linux       | 1.85+ | `gcc` + `make`                 | `libpcap-dev` (or -devel)     |
| macOS       | 1.85+ | Xcode Command Line Tools       | `brew install libpcap`        |
| Windows MSVC| 1.85+ | VS 2022 Build Tools (C++)      | Npcap runtime + SDK           |
| Windows GNU | 1.85+ | mingw-w64 (e.g. WinLibs)       | Npcap runtime + SDK (+ rename)|

Once the default build succeeds on any of those, you can iterate
with `cargo build` as usual.
