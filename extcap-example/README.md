Rust port of https://gitlab.com/wireshark/wireshark/-/blob/master/doc/extcap_example.py.

This is a separate cargo project instead of being a `[[example]]` to enable automated CLI testing using `assert_cmd`.

To test this, copy the following into an executable bash script under Personal Extcap Folder, which is `~/.local/lib/wireshark/extcap` for Wireshark 4.1 or later, or `~/.config/wireshark/extcap` on Wireshark 4.0 or before.

```sh
#! /usr/bin/env bash
exec 2>/tmp/extcap-example.log
# Use exec to make sure the rust program will get SIGTERM from wireshark when stopping
RUST_LOG=debug exec /Users/mauricelam/Desktop/btsnoop-rs/target/debug/extcap-example "$@"
```
