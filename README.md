# r-extcap

[![Build status](https://github.com/mauricelam/r-extcap/actions/workflows/rust.yml/badge.svg)](https://github.com/mauricelam/r-extcap/actions)
[![Crates.io](https://img.shields.io/crates/v/r-extcap.svg)](https://crates.io/crates/r-extcap)
[![Docs.rs](https://img.shields.io/badge/docs-rustdoc-green)](https://docs.rs/r-extcap)

<!-- cargo-rdme start -->

Write [extcap](https://www.wireshark.org/docs/man-pages/extcap.html)
programs in Rust.

The extcap interface is a versatile plugin interface used by Wireshark to
allow external binaries to act as capture interfaces. The extcap interface
itself is generic and can be used by applications other than Wireshark, like
Wireshark's command line sibling `tshark`. For the sake of brevity, in the
documentation we will refer to the host application simply as Wireshark.

#### Extcap overview

1. `--extcap-interfaces`: In this step, Wireshark asks the extcap for its
   list of supported interfaces, version metadata, and the list of toolbar
   controls.
2. `--extcap-dlts`: Invoked once for each interface, Wireshark asks the
   extcap program for the data link type associated with the interface.
3. `--extcap-config`: Invoked for each interface upon user request,
   Wireshark asks the extcap program for a list of configurations to
   populate a config dialog in the UI.
4. `--capture`: The main part of the extcap program – invoked once when the
   user selects an interface for capture, to tell the extcap to start
   capturing packets. Captured packets should be written to the `--fifo` in
   the PCAP format.

### Getting started

To create an extcap using this library, these are the high level steps:

1. Create a struct with `#[derive(clap::Parser)]`, and add
   [`ExtcapArgs`](https://docs.rs/r-extcap/latest/r_extcap/struct.ExtcapArgs.html) as one of the fields with the
   `#[command(flatten)]` attribute.

   ```rust
   #[derive(Debug, clap::Parser)]
   struct AppArgs {
       #[command(flatten)]
       extcap: r_extcap::ExtcapArgs,

       // Other args for extcap (see the `configs` module)
   }
   ```

2. In a `lazy_static`, define the necessary
   [interfaces](https://docs.rs/r-extcap/latest/r_extcap/interface/struct.Interface.html), [toolbar
   controls](https://docs.rs/r-extcap/latest/r_extcap/controls/trait.ToolbarControl.html), and
   [configs](https://docs.rs/r-extcap/latest/r_extcap/config/trait.ConfigTrait.html). If you are unsure, you can simply
   start with the [`Interfaces`](https://docs.rs/r-extcap/latest/r_extcap/interface/struct.Interface.html) you want to
   capture and add the others later as needed.

3. In the `main` function, parse the arguments and call
   [`ExtcapArgs::run`](https://docs.rs/r-extcap/latest/r_extcap/struct.ExtcapArgs.html#method.run). Use the returned
   [`ExtcapStep`](https://docs.rs/r-extcap/latest/r_extcap/enum.ExtcapStep.html) to perform the requested operation.
   There are 5 steps:

    1. [`InterfacesStep`](https://docs.rs/r-extcap/latest/r_extcap/struct.InterfacesStep.html): List the interfaces that
           can be captured by this program, as well as the metadata and
           toolbar controls associated.
    2. [`DltsStep`](https://docs.rs/r-extcap/latest/r_extcap/struct.DltsStep.html): Prints the DLTs for a given interface.
    3. [`ConfigStep`](https://docs.rs/r-extcap/latest/r_extcap/struct.ConfigStep.html): Optional, provide a list of UI
           configuration options that the user can change.
    4. [`ReloadConfigStep`](https://docs.rs/r-extcap/latest/r_extcap/struct.ReloadConfigStep.html): Optional, if
           [`SelectorConfig::reload`](https://docs.rs/r-extcap/latest/r_extcap/config/struct.SelectorConfig.html)
           is configured in one of the configs, invoked to reload the list
           of options the user can choose from.
    5. [`CaptureStep`](https://docs.rs/r-extcap/latest/r_extcap/struct.CaptureStep.html): described below.

 4. In the [`CaptureStep`](https://docs.rs/r-extcap/latest/r_extcap/struct.CaptureStep.html), start capturing packets from
   the external interface, and write the packets to
   [`CaptureStep::fifo`](https://docs.rs/r-extcap/latest/r_extcap/struct.CaptureStep.html) using the
   [`pcap_file`](https://docs.rs/pcap-file/latest/pcap_file/index.html)
   crate.

## Example

```rust
use clap::Parser;
use r_extcap::{cargo_metadata, ExtcapArgs, ExtcapStep, interface::*, controls::*, config::*};

#[derive(Debug, Parser)]
struct AppArgs {
    #[command(flatten)]
    extcap: ExtcapArgs,
}

lazy_static! {
    // static ref CONFIG_FOO: SelectorConfig = ...;
    // static ref CONFIG_BAR: StringConfig = ...;

    // static ref CONTROL_A: BooleanControl = ...;

    // static ref INTERFACE_1: Interface = ...;
}

fn main() -> anyhow::Result<()> {
    match AppArgs::parse().extcap.run()? {
        ExtcapStep::Interfaces(interfaces_step) => {
            interfaces_step.list_interfaces(
                &cargo_metadata!(),
                &[
                    // &*INTERFACE_1,
                ],
                &[
                    // &*CONTROL_A,
                    // &*CONTROL_B,
                ],
            );
        }
        ExtcapStep::Dlts(dlts_step) => {
            dlts_step.print_from_interfaces(&[
                // &*INTERFACE_1,
            ])?;
        }
        ExtcapStep::Config(config_step) => config_step.list_configs(&[
            // &*CONFIG_FOO,
            // &*CONFIG_BAR,
        ]),
        ExtcapStep::ReloadConfig(reload_config_step) => {
            reload_config_step.reload_from_configs(&[
                // &*CONFIG_FOO,
                // &*CONFIG_BAR,
            ])?;
        }
        ExtcapStep::Capture(capture_step) => {
            // Run capture
        }
    }
    Ok(())
}
```

References:
* <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html>
* <https://www.wireshark.org/docs/man-pages/extcap.html>
* <https://gitlab.com/wireshark/wireshark/-/blob/master/doc/extcap_example.py>

<!-- cargo-rdme end -->

# Contributions

Contributions of any form are appreciated. New features, bug fixes,
documentation improvements, additional tests, or PRs with failing test cases are
welcome.
