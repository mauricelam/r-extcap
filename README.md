# Write Wireshark extcap programs in Rust

### [Documentation](https://docs.rs/r-extcap/latest)

The extcap interface is a versatile plugin interface used by Wireshark to
allow external binaries to act as capture interfaces. The extcap interface
itself is generic and can be used by applications other than Wireshark, like
Wireshark's command line sibling `tshark`. For the sake of brevity, in the
documentation we will refer to the host application simply as Wireshark.

### Extcap overview

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

## Getting started

To create an extcap using this library, these are the high level steps:

1. Create a struct with `#[derive(clap::Parser)]`, and add `ExtcapArgs` as
   one of the fields with the `#[command(flatten)]` attribute.

   ```rs
   #[derive(Debug, clap::Parser)]
   struct AppArgs {
       #[command(flatten)]
       extcap: r_extcap::ExtcapArgs,

       // Other args for extcap (see the `configs` module)
   }
   ```

2. Create a struct that implements `ExtcapApplication`. It is recommended
   to define the application in a `lazy_static`. There 4 things need to be
   provided for an extcap implementation:

    1. `metadata`: The version information and metadata for this program,
            used by Wireshark to display in the UI.
    2. `interfaces`: The list of interfaces
           that can be captured by this program.
    3. `toolbar_controls`: Optional,
           a list of toolbar controls shown in the Wireshark UI.
    4. `configs`: Optional, a list of UI
           configuration options that the user can change.

3. In the `main` function, parse the arguments and call `ExtcapArgs::run`.
   Use the returned `CaptureContext` to start capturing packets, and write
   the packets to `CaptureContext::fifo` using the
   [`pcap_file`](https://docs.rs/pcap-file/latest/pcap_file/index.html)
   crate.

   ```rs
   fn main() -> anyhow::Result<()> {
       if let Some(capture_context) = AppArgs::parse().extcap.run(&*APPLICATION)? {
           // Run capture
       }
       Ok(())
   }
   ```

# Example

```rs
use lazy_static::lazy_static;
use clap::Parser;
use r_extcap::{ExtcapApplication, ExtcapArgs};
use r_extcap::{interface::*, controls::*, config::*};

struct ExampleExtcapApplication {}
impl ExtcapApplication for ExampleExtcapApplication {
      fn metadata(&self) -> &Metadata { todo!() }
      fn interfaces(&self) -> &[Interface] { todo!() }
      fn toolbar_controls(&self) -> Vec<&dyn ToolbarControl> { todo!() }
      fn configs(&self, interface: &Interface) -> Vec<&dyn ConfigTrait> { todo!() }
}

#[derive(Debug, Parser)]
struct AppArgs {
    #[command(flatten)]
    extcap: ExtcapArgs,
}

lazy_static! {
    static ref APPLICATION: ExampleExtcapApplication = ExampleExtcapApplication {
        // ...
    };
}

fn main() -> anyhow::Result<()> {
    if let Some(capture_context) = AppArgs::parse().extcap.run(&*APPLICATION)? {
        // Run capture
    }
    Ok(())
}
```

References:
* <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html>
* <https://www.wireshark.org/docs/man-pages/extcap.html>
* <https://gitlab.com/wireshark/wireshark/-/blob/master/doc/extcap_example.py>