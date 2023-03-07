//! Write [extcap](https://www.wireshark.org/docs/man-pages/extcap.html)
//! programs in Rust.
//!
//! The extcap interface is a versatile plugin interface used by Wireshark to
//! allow external binaries to act as capture interfaces. The extcap interface
//! itself is generic and can be used by applications other than Wireshark, like
//! Wireshark's command line sibling `tshark`. For the sake of brevity, in the
//! documentation we will refer to the host application simply as Wireshark.
//!
//! ### Extcap overview
//!
//! 1. `--extcap-interfaces`: In this step, Wireshark asks the extcap for its
//!    list of supported interfaces, version metadata, and the list of toolbar
//!    controls.
//! 2. `--extcap-dlts`: Invoked once for each interface, Wireshark asks the
//!    extcap program for the data link type associated with the interface.
//! 3. `--extcap-config`: Invoked for each interface upon user request,
//!    Wireshark asks the extcap program for a list of configurations to
//!    populate a config dialog in the UI.
//! 4. `--capture`: The main part of the extcap program – invoked once when the
//!    user selects an interface for capture, to tell the extcap to start
//!    capturing packets. Captured packets should be written to the `--fifo` in
//!    the PCAP format.
//!
//! ## Getting started
//!
//! To create an extcap using this library, these are the high level steps:
//!
//! 1. Create a struct with `#[derive(clap::Parser)]`, and add
//!    [`ExtcapArgs`](crate::ExtcapArgs) as one of the fields with the
//!    `#[command(flatten)]` attribute.
//!
//!    ```
//!    #[derive(Debug, clap::Parser)]
//!    struct AppArgs {
//!        #[command(flatten)]
//!        extcap: r_extcap::ExtcapArgs,
//!
//!        // Other args for extcap (see the `configs` module)
//!    }
//!    ```
//!
//! 2. In a `lazy_static`, define the necessary
//!    [interfaces](crate::interface::Interface), [toolbar
//!    controls](crate::controls::ToolbarControl), and
//!    [configs](crate::config::ConfigTrait). If you are unsure, you can simply
//!    start with the [`Interfaces`](crate::interface::Interface) you want to
//!    capture and add the others later as needed.
//!
//! 3. In the `main` function, parse the arguments and call
//!    [`ExtcapArgs::run`](crate::ExtcapArgs::run). Use the returned
//!    [`ExtcapStep`](crate::ExtcapStep) to perform the requested operation.
//!    There are 5 steps:
//!
//!     1. [`InterfacesStep`](crate::InterfacesStep): List the interfaces that
//!            can be captured by this program, as well as the metadata and
//!            toolbar controls associated.
//!     2. [`DltsStep`](crate::DltsStep): Prints the DLTs for a given interface.
//!     3. [`ConfigStep`](crate::ConfigStep): Optional, provide a list of UI
//!            configuration options that the user can change.
//!     4. [`ReloadConfigStep`](crate::ReloadConfigStep): Optional, if
//!            [`SelectorConfig::reload`](crate::config::SelectorConfig)
//!            is configured in one of the configs, invoked to reload the list
//!            of options the user can choose from.
//!     5. [`CaptureStep`](crate::CaptureStep): described below.
//!
//!  4. In the [`CaptureStep`](crate::CaptureStep), start capturing packets from
//!    the external interface, and write the packets to
//!    [`CaptureStep::fifo`](crate::CaptureStep) using the
//!    [`pcap_file`](https://docs.rs/pcap-file/latest/pcap_file/index.html)
//!    crate.
//!
//! # Example
//!
//! ```no_run
//! # use lazy_static::lazy_static;
//! use clap::Parser;
//! use r_extcap::{cargo_metadata, ExtcapArgs, ExtcapStep, interface::*, controls::*, config::*};
//!
//! #[derive(Debug, Parser)]
//! struct AppArgs {
//!     #[command(flatten)]
//!     extcap: ExtcapArgs,
//! }
//!
//! lazy_static! {
//!     // static ref CONFIG_FOO: SelectorConfig = ...;
//!     // static ref CONFIG_BAR: StringConfig = ...;
//!
//!     // static ref CONTROL_A: BooleanControl = ...;
//!
//!     // static ref INTERFACE_1: Interface = ...;
//! }
//!
//! fn main() -> anyhow::Result<()> {
//!     match AppArgs::parse().extcap.run()? {
//!         ExtcapStep::Interfaces(interfaces_step) => {
//!             interfaces_step.list_interfaces(
//!                 &cargo_metadata!(),
//!                 &[
//!                     // &*INTERFACE_1,
//!                 ],
//!                 &[
//!                     // &*CONTROL_A,
//!                     // &*CONTROL_B,
//!                 ],
//!             );
//!         }
//!         ExtcapStep::Dlts(dlts_step) => {
//!             dlts_step.print_from_interfaces(&[
//!                 // &*INTERFACE_1,
//!             ])?;
//!         }
//!         ExtcapStep::Config(config_step) => config_step.list_configs(&[
//!             // &*CONFIG_FOO,
//!             // &*CONFIG_BAR,
//!         ]),
//!         ExtcapStep::ReloadConfig(reload_config_step) => {
//!             reload_config_step.reload_from_configs(&[
//!                 // &*CONFIG_FOO,
//!                 // &*CONFIG_BAR,
//!             ])?;
//!         }
//!         ExtcapStep::Capture(capture_step) => {
//!             // Run capture
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! References:
//! * <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html>
//! * <https://www.wireshark.org/docs/man-pages/extcap.html>
//! * <https://gitlab.com/wireshark/wireshark/-/blob/master/doc/extcap_example.py>

#![warn(missing_docs)]

use clap::Args;
use config::{ConfigTrait, SelectorConfig};
use controls::ToolbarControl;
use interface::{Interface, Metadata};
use std::{
    fmt::Display,
    fs::File,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub mod config;
pub mod controls;
pub mod interface;

/// The arguments defined by extcap. These arguments are usable as a clap
/// parser.
///
/// For example, if you use `clap` with the feature `derive`:
/// ```
/// # use clap::Parser;
/// #[derive(Debug, Parser)]
/// #[command(author, version, about)]
/// pub struct ApplicationArgs {
///    #[command(flatten)]
///    extcap: r_extcap::ExtcapArgs,
///
///    // Other application args
/// }
/// ```
///
/// Wireshark will call extcap in 4 phases:
///
/// 1. [`--extcap-interfaces`][ExtcapArgs::extcap_interfaces]: Declare all
///    supported interfaces and controls.
/// 2. [`--extcap-config`][ExtcapArgs::extcap_config]: Called for each interface
///    to declare configuration options that can be changed by the user in the
///    UI. (This is used only in Wireshark, not available in tshark).
/// 3. [`--extcap-dlts`][ExtcapArgs::extcap_dlts]: Called for each interface
///    returned in `--extcap-interfaces` to specify which Data Link Type is
///    being captured.
/// 4. [`--capture`][ExtcapArgs::capture]: Called to initiate capture of the
///    packets. See the documentation on the field for details.
///
/// When the capturing stops (i.e. the user presses the red Stop button),
/// `SIGTERM` is sent by Wireshark.
#[derive(Debug, Args)]
pub struct ExtcapArgs {
    /// First step in the extcap exchange: this program is queried for its
    /// interfaces.
    /// ```sh
    /// $ extcapbin --extcap-interfaces
    /// ```
    /// This call must print the existing interfaces for this extcap and must
    /// return 0. The output must conform to the grammar specified in the
    /// [doc/extcap.4](https://www.wireshark.org/docs/man-pages/extcap.html)
    /// man pages.
    #[arg(long, verbatim_doc_comment)]
    pub extcap_interfaces: bool,

    /// The version of Wireshark (or tshark) calling into this extcap.
    ///
    /// Wireshark 2.9 and later pass `--extcap-version=x.x` when querying for
    /// the list of interfaces, which provides the calling Wireshark's major and
    /// minor version. This can be used to change behavior depending on the
    /// Wireshark version in question.
    ///
    /// This argument is passed during the
    /// [`--extcap-interfaces`][ExtcapArgs::extcap_interfaces] call.
    #[arg(long)]
    pub extcap_version: Option<String>,

    /// Second step in the extcap exchange: this program is asked for the configuration of each
    /// specific interface
    /// ```sh
    /// $ extcap_example.py --extcap-interface <iface> --extcap-config
    /// ```
    ///
    /// Each interface can have custom options that are valid for this interface only. Those config
    /// options are specified on the command line when running the actual capture. To allow an
    /// end-user to specify certain options, such options may be provided using the extcap config
    /// argument.
    ///
    /// To share which options are available for an interface, the extcap responds to the command
    /// `--extcap-config`, which shows all the available options (aka additional command line
    /// options).
    ///
    /// Those options are used to build a configuration dialog for the interface.
    #[arg(long, verbatim_doc_comment)]
    pub extcap_config: bool,

    /// Third step in the extcap exchange: the extcap binary is queried for all valid DLTs for all
    /// the interfaces returned during [`--extcap-interfaces`][Self::extcap_interfaces]).
    ///
    /// ```sh
    /// $ extcap_example.py --extcap-dlts --extcap-interface <iface>
    /// ```
    ///
    /// This call must print the valid DLTs for the interface specified. This call is made for all
    /// the interfaces and must return exit code 0.
    ///
    /// Example for the DLT query.
    /// ```sh
    /// $ extcap_example.py --extcap-interface IFACE --extcap-dlts
    /// dlt {number=147}{name=USER1}{display=Demo Implementation for Extcap}
    /// ```
    ///
    /// A binary or script which neither provides an interface list or a DLT list will not show up
    /// in the extcap interfaces list.
    #[arg(long, requires = "extcap_interface", verbatim_doc_comment)]
    pub extcap_dlts: bool,

    /// Start the capturing phase.
    ///
    /// In addition to `--capture`, the
    /// [`--extcap-capture-filter`][ExtcapArgs::extcap_capture_filter] and
    /// [`--fifo`][ExtcapArgs::fifo] options are also required in this phase.
    ///
    /// Additionally, if `{config}` entries were returned during the
    /// `--extcap-interfaces` phase, then
    /// [`--extcap-control-in`][ExtcapArgs::extcap_control_in] and
    /// [`--extcap-control-out`][ExtcapArgs::extcap_control_out] will be passed,
    /// which are a pair of fifos in which [control
    /// messages](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html#_messages)
    /// are sent.
    #[arg(long, requires = "fifo", requires = "extcap_interface")]
    pub capture: bool,

    /// The extcap interface to perform the operation on.
    ///
    /// This should match one of the values returned earlier in
    /// [`extcap_interfaces`][Self::extcap_interfaces], and is used in the
    /// [`capture`][Self::capture], [`extcap_config`][Self::extcap_config], and
    /// [`extcap_dlts`][Self::extcap_dlts] phases.
    #[arg(long)]
    pub extcap_interface: Option<String>,

    /// Specifies the fifo for the packet captures. The extcap implementation
    /// should write the captured packets to this fifo in pcap or pcapng format.
    #[arg(long, requires = "capture")]
    pub fifo: Option<PathBuf>,

    /// The capture filter provided by wireshark. This extcap should avoid capturing packets that do
    /// not match this filter. Used during the `--capture` phase.
    #[arg(long, requires = "capture")]
    pub extcap_capture_filter: Option<String>,

    /// Used to get control messages from toolbar. Control messages are in the
    /// format documented in [`ControlPacket`][controls::ControlPacket].
    #[arg(long, requires = "capture")]
    pub extcap_control_in: Option<PathBuf>,

    /// Used to send control messages to toolbar. Control messages are in the
    /// format documented in [`ControlPacket`][controls::ControlPacket].
    #[arg(long, requires = "capture")]
    pub extcap_control_out: Option<PathBuf>,

    /// A [`SelectorConfig`] may be reloaded from the configuration dialog of
    /// the extcap application within Wireshark. With [`SelectorConfig::reload`]
    /// (defaults to `false`), the entry can be marked as reloadable.
    ///
    /// ```
    /// use r_extcap::config::{ConfigOptionValue, SelectorConfig, Reload};
    ///
    /// SelectorConfig::builder()
    ///     .config_number(3)
    ///     .call("remote")
    ///     .display("Remote Channel")
    ///     .tooltip("Remote Channel Selector")
    ///     .reload(Reload {
    ///         label: String::from("Load interfaces..."),
    ///         reload_fn: || {
    ///             vec![
    ///                 ConfigOptionValue::builder()
    ///                     .value("if3")
    ///                     .display("Remote Interface 3")
    ///                     .default(true)
    ///                     .build(),
    ///                 ConfigOptionValue::builder()
    ///                     .value("if4")
    ///                     .display("Remote Interface 4")
    ///                     .build(),
    ///             ]
    ///         }
    ///     })
    ///     .default_options([
    ///         ConfigOptionValue::builder()
    ///             .value("if1")
    ///             .display("Remote1")
    ///             .default(true)
    ///             .build(),
    ///         ConfigOptionValue::builder().value("if2").display("Remote2").build(),
    ///     ])
    ///     .build();
    /// ```
    ///
    /// After this has been defined, the user will get a button displayed in the
    /// configuration dialog for this extcap application, with the text "Load
    /// interfaces...​".
    ///
    /// The extcap utility is then called again with all filled out arguments
    /// and the additional parameter `--extcap-reload-option <option_name>`. It
    /// is expected to return a value section for this option, as it would
    /// during normal configuration. The provided option list is then presented
    /// as the selection, a previous selected option will be reselected if
    /// applicable.
    #[arg(long, requires = "extcap_interface")]
    pub extcap_reload_option: Option<String>,
}

/// Error during the `--capture` phase of extcap.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// The `--extcap-interface` argument is required during the `--capture`
    /// phase of extcap, but is not provided.
    #[error("Missing `--extcap-interface` argument during `--capture` phase")]
    MissingInterface,
    /// Error caused by missing `--fifo` argument from the command line. This is
    /// expected to be passed by Wireshark when invoking an extcap for
    /// capturing, and is needed to write the output of the packet capture to.
    #[error(
        "--fifo argument is missing. This is expected to be included \
when invoked by Wireshark during the capture stage."
    )]
    MissingFifo,
    /// IO Error while trying to open the given fifo. Since the fifo is
    /// necessary to send the captured packets to Wireshark, implementations are
    /// recommended to clean up and terminate the execution. Additionally, the
    /// error can be printed onto stderr. If Wireshark picks that up, it will
    /// show that to the user in an error dialog.
    #[error("IO error opening output FIFO for capture")]
    Io(#[from] std::io::Error),
}

impl ExtcapArgs {
    /// Runs the extcap program with the parsed arguments. This is the main
    /// entry point for the extcap program. Implementations should call this
    /// from their `main` functions.
    ///
    /// For detailed usage, see the [crate documentation][crate]
    pub fn run(&self) -> Result<ExtcapStep, ExtcapError> {
        if self.extcap_interfaces {
            Ok(ExtcapStep::Interfaces(InterfacesStep))
        } else if let Some(interface) = &self.extcap_interface {
            if self.extcap_config {
                if let Some(reload_config) = &self.extcap_reload_option {
                    Ok(ExtcapStep::ReloadConfig(ReloadConfigStep {
                        interface,
                        config: reload_config,
                    }))
                } else {
                    Ok(ExtcapStep::Config(ConfigStep { interface }))
                }
            } else if self.extcap_dlts {
                Ok(ExtcapStep::Dlts(DltsStep { interface }))
            } else if self.capture {
                let fifo_path = self.fifo.as_ref().ok_or(CaptureError::MissingFifo)?;
                let fifo = File::create(fifo_path).map_err(CaptureError::Io)?;
                let interface = self
                    .extcap_interface
                    .as_ref()
                    .ok_or(CaptureError::MissingInterface)?;
                Ok(ExtcapStep::Capture(CaptureStep {
                    interface,
                    // Note: It is important to open this file, so the file gets
                    // closed even if the implementation doesn't use it.
                    // Otherwise Wireshark will hang there waiting for the FIFO.
                    fifo,
                    fifo_path,
                    extcap_control_in: &self.extcap_control_in,
                    extcap_control_out: &self.extcap_control_out,
                }))
            } else {
                Err(ExtcapError::NotExtcapInput)
            }
        } else {
            Err(ExtcapError::NotExtcapInput)
        }
    }
}

/// Error reported when running [`ExtcapArgs::run`].
#[derive(Debug, Error)]
pub enum ExtcapError {
    /// The inputs given are not expected input from Wireshark. This can happen
    /// for example, when the user tries to run the application directly from
    /// command line. When this happens, you can print out the
    /// [`installation_instructions`], to help the user install this in the
    /// right location.
    #[error("Missing input extcap command. {}", installation_instructions())]
    NotExtcapInput,

    /// Error when capturing packets. See [`CaptureError`].
    #[error(transparent)]
    CaptureError(#[from] CaptureError),
}

/// Get the installation instructions. This is useful to show if the program is
/// used in unexpected ways (e.g. not as an extcap program), so users can easily
/// install with a copy-pastable command.
///
/// ```
/// # use indoc::formatdoc;
/// # let exe = std::env::current_exe().unwrap();
/// # let executable_path = exe.to_string_lossy();
/// # let exe_name = exe.file_name().unwrap().to_string_lossy();
/// assert_eq!(
///     r_extcap::installation_instructions(),
///     formatdoc!{"
///         This is an extcap plugin meant to be used with Wireshark or tshark.
///         To install this plugin for use with Wireshark, symlink or copy this executable \
///         to your Wireshark extcap directory
///           mkdir -p ~/.config/wireshark/extcap/ && ln -s \"{executable_path}\" \"~/.config/wireshark/extcap/{exe_name}\"\
///     "}
/// )
/// ```
pub fn installation_instructions() -> String {
    let install_cmd = std::env::current_exe()
        .ok()
        .and_then(|exe| {
            let path = exe.to_string_lossy();
            let name = exe.file_name()?.to_string_lossy();
            Some(format!("\n  mkdir -p ~/.config/wireshark/extcap/ && ln -s \"{path}\" \"~/.config/wireshark/extcap/{name}\""))
        })
        .unwrap_or_default();
    format!(
        concat!(
            "This is an extcap plugin meant to be used with Wireshark or tshark.\n",
            "To install this plugin for use with Wireshark, symlink or copy this executable ",
            "to your Wireshark extcap directory{}",
        ),
        install_cmd
    )
}

/// Error printing DLTs to Wireshark.
#[derive(Debug, Error)]
pub enum PrintDltError {
    /// The interface string value given from Wireshark is not found. Wireshark
    /// invokes the extcap program multiple times, first to get the list of
    /// interfaces, then multiple times to get the DLTs. Therefore,
    /// implementations should make sure that the list of interfaces stay
    /// consistent, or be prepared to gracefully handle this error.
    #[error("Cannot list DLT for unknown interface \"{0}\".")]
    UnknownInterface(String),
}

/// Error when reloading configs. Config reload happens when a config, like
/// [`crate::config::SelectorConfig`] specifics the `reload` field and the user
/// clicks on the created reload button.
#[derive(Debug, Error)]
pub enum ReloadConfigError {
    /// The config `call` value given from Wireshark is not found in the configs
    /// provided. Wireshark makes separate invocations to get the initial list
    /// of interfaces, and when the user subsequently hits reload on a config.
    /// Therefore, implementations should make sure that the configs used in
    /// [`ConfigStep`] and [`ReloadConfigStep`] are consistent.
    #[error("Cannot reload options for unknown config \"{0}\".")]
    UnknownConfig(String),

    /// The config given by Wireshark is found, but it is not a
    /// [`SelectorConfig`]. This configuration is not expected to be invoked by
    /// Wireshark, as the [`SelectorConfig::reload`] field only exists for the
    /// appropriate types.
    #[error("Cannot reload config options for \"{0}\", which is not of type \"selector\".")]
    UnsupportedConfig(String),
}

/// Error listing configs.
#[derive(Debug, Error)]
pub enum ListConfigError {
    /// The interface string value given from Wireshark is not found. Wireshark
    /// makes separate invocations to get the initial list of interfaces, and
    /// when the user subsequently opens the config dialog. Therefore,
    /// implementations should make sure that the interfaces used in different
    /// [`ExtcapSteps`][ExtcapStep] are deterministic and doesn't change across
    /// invocations of the program.
    #[error("Cannot reload config options for unknown interface \"{0}\".")]
    UnknownInterface(String),
}

/// The step of extcap to execute, which is returned from [`ExtcapArgs::run`].
/// Each step has its own type which contains the relevant methods for each
/// step. See the docs for each individual step to for details on what
/// operations should be performed.
pub enum ExtcapStep<'a> {
    /// List the interfaces and toolbar controls supported by this extcap
    /// implementation in stdout for Wireshark's consumption. Corresponds to the
    /// `--extcap-interfaces` argument in extcap.
    ///
    /// See the documentation on [`InterfacesStep`] for details.
    Interfaces(InterfacesStep),
    /// Prints the DLT to stdout for consumption by Wireshark. Corresponds to
    /// the `--extcap-dlts` argument in extcap.
    ///
    /// See the documentation on [`DltsStep`] for details.
    Dlts(DltsStep<'a>),
    /// List the configs available for the given interface in stdout for
    /// Wireshark's consumption. Corresponds to the `--extcap-config` argument
    /// in extcap.
    ///
    /// See the documentation on [`ConfigStep`] for details.
    Config(ConfigStep<'a>),
    /// Reloads the available options for a given config and prints them out for
    /// Wireshark's consumption. The default implementation looks up config returned from `configs` and calls its reload function. Corresponds to the `--extcap-reload-option`
    /// argument in extcap.
    ///
    /// See the documentation on [`ReloadConfigStep`] for details.
    ReloadConfig(ReloadConfigStep<'a>),
    /// Corresponds to the `--capture` step in Wireshark. In this step, the
    /// implementation should start capturing from the external interface and
    /// write the output to the fifo given in [`CaptureStep::fifo`].
    ///
    /// See the documentation on [`CaptureStep`] for details.
    Capture(CaptureStep<'a>),
}

/// List the interfaces and toolbar controls supported by this extcap
/// implementation in stdout for Wireshark's consumption. Corresponds to the
/// `--extcap-interfaces` argument in extcap. Implementations should call
/// [`list_interfaces`][Self::list_interfaces] during this step.
pub struct InterfacesStep;

impl InterfacesStep {
    /// List the interfaces and toolbar controls supported by this extcap
    /// implementation in stdout for Wireshark's consumption. Wireshark calls
    /// this when the application starts up to populate the list of available
    /// interfaces.
    ///
    /// * metadata: metadata like version info and help URL for this program.
    ///   This is used by Wireshark to display in the UI.
    ///
    ///   The [`cargo_metadata`] macro can be used to create this from data in
    ///   `Cargo.toml`.
    /// * interfaces: List of interfaces to make available for external capture.
    ///   Since that interface list is cached and the interface names can be
    ///   used later when the user tries to start a capture session, the
    ///   interface list should stay as consistent as possible. If the list of
    ///   interfaces can change, the extcap program must be prepared to handle
    ///   stale values in [`ConfigStep::interface`] and
    ///   [`CaptureStep::interface`].
    /// * controls: List the toolbar controls for this interface. In Wireshark,
    ///   this is presented to the user in View > Interface Toolbars. See the
    ///   documentation in [`controls`] for details.
    pub fn list_interfaces(
        &self,
        metadata: &Metadata,
        interfaces: &[&Interface],
        controls: &[&dyn ToolbarControl],
    ) {
        metadata.print_sentence();
        for interface in interfaces {
            interface.print_sentence();
        }
        for control in controls {
            control.print_sentence();
        }
    }
}

/// In the DLTs step, Wireshark asks the extcap program for the DLT for each
/// interface. DLT stands for data link type, and is used to determine how
/// Wireshark analyzes (dissects) the given packets.
///
/// Despite this step being named with plurals (DLTs) by extcap, only one DLT is
/// expected for each interface. Corresponds to the `--extcap-dlts` argument in
/// extcap.
pub struct DltsStep<'a> {
    /// The interface to print the DLT for.
    pub interface: &'a str,
}

impl<'a> DltsStep<'a> {
    /// Print the DLT for the given interface. If you have the list of
    /// interfaces from [`InterfacesStep`], consider using
    /// [`print_from_interfaces`][Self::print_from_interfaces] instead.
    pub fn print_dlt(&self, interface: &Interface) {
        interface.dlt.print_sentence();
    }

    /// Finds the interface within `interfaces` that matches the given request
    /// and prints out its DLT. Typically `interfaces` will be the same list
    /// given to [`InterfacesStep::list_interfaces`].
    pub fn print_from_interfaces(&self, interfaces: &[&Interface]) -> Result<(), PrintDltError> {
        interfaces
            .iter()
            .find(|i| i.value == self.interface)
            .ok_or_else(|| PrintDltError::UnknownInterface(self.interface.to_owned()))?
            .dlt
            .print_sentence();
        Ok(())
    }
}

/// List the configurable UI elements for this interface. This is presented to
/// the user when they click on the gear icon next to the capture interface
/// name, or if they try to start a capture that is lacking a required config
/// value.
pub struct ConfigStep<'a> {
    /// The interface that the configurations should be associated with.
    pub interface: &'a str,
}

impl<'a> ConfigStep<'a> {
    /// List the `configs` given, printing them out to stdout for consumption by
    /// Wireshark. This list can vary by [`interface`].
    pub fn list_configs(&self, configs: &[&dyn ConfigTrait]) {
        for config in configs {
            config.print_sentence();
        }
    }
}

/// Reload operation for a particular configuration. This is invoked when the
/// user clicks on the reload button created by a [`SelectorConfig`] with the
/// [`reload`][SelectorConfig::reload] field set. Corresponds to the
/// `--extcap-reload-option` argument in extcap.
pub struct ReloadConfigStep<'a> {
    /// The [`Interface::value`] from the interface the reloaded config is
    /// associated with.
    pub interface: &'a str,
    /// The [`ConfigTrait::call`] of the config being reloaded.
    pub config: &'a str,
}

impl<'a> ReloadConfigStep<'a> {
    /// Calls the [`reload`][SelectorConfig::reload] function in the given
    /// `config`. Returns the error [`ReloadConfigError::UnsupportedConfig`] if
    /// the given config does not have `reload` set.
    ///
    /// If you have the list of configs for the given interface, consider using
    /// [`reload_from_configs`][Self::reload_from_configs] instead.
    pub fn reload_options(&self, config: &SelectorConfig) -> Result<(), ReloadConfigError> {
        let reload = config
            .reload
            .as_ref()
            .ok_or_else(|| ReloadConfigError::UnsupportedConfig(config.call.clone()))?;
        for value in (reload.reload_fn)() {
            value.print_sentence(config.config_number);
        }
        Ok(())
    }

    /// Process config reload request using the list of `configs`. This list is
    /// typically the same as the one given to [`ConfigStep::list_configs`].
    pub fn reload_from_configs(
        &self,
        configs: &[&dyn ConfigTrait],
    ) -> Result<(), ReloadConfigError> {
        let config = configs
            .iter()
            .find(|c| c.call() == self.config)
            .ok_or_else(|| ReloadConfigError::UnknownConfig(self.config.to_owned()))?;
        let selector = config
            .as_any()
            .downcast_ref::<SelectorConfig>()
            .ok_or_else(|| ReloadConfigError::UnsupportedConfig(self.config.to_owned()))?;
        self.reload_options(selector)
    }
}

/// When this value is returned in [`ExtcapArgs::run`], the implementation
/// should use these returned values to start capturing packets from the
/// external interface and write them to the [`fifo`][Self::fifo] in PCAP
/// format.
pub struct CaptureStep<'a> {
    /// The interface to run this capture on. This is the string previously
    /// defined in [`Interface::value`].
    pub interface: &'a str,
    /// The fifo to write the output packets to. The output packets should be
    /// written in PCAP format. Implementations can use the
    /// [`pcap-file`](https://docs.rs/pcap-file/latest/pcap_file/) crate to help
    /// format the packets.
    pub fifo: std::fs::File,
    fifo_path: &'a Path,
    /// The extcap control reader if the `--extcap-control-in` argument is
    /// provided on the command line. This is used to receive arguments from the
    /// toolbar controls and other control messages from Wireshark.
    pub extcap_control_in: &'a Option<std::path::PathBuf>,
    /// The extcap control sender if the `--extcap-control-out` argument is
    /// provided on the command line. This is used to send control messages to
    /// Wireshark to modify the toolbar controls and show status messages.
    pub extcap_control_out: &'a Option<std::path::PathBuf>,
}

impl<'a> CaptureStep<'a> {
    /// Create a new control sender for this capture, if `--extcap-control-out`
    /// is specified in the command line. The control sender is used to send
    /// control messages to Wireshark to modify
    /// [`ToolbarControls`][controls::ToolbarControl] and communicate other
    /// states.
    #[cfg(feature = "sync")]
    pub fn new_control_sender(&self) -> Option<controls::synchronous::ExtcapControlSender> {
        self.extcap_control_out
            .as_ref()
            .map(|p| controls::synchronous::ExtcapControlSender::new(p))
    }

    /// Create a new control sender for this capture, if `--extcap-control-out`
    /// is specified in the command line. The control sender is used to send
    /// control messages to Wireshark to modify
    /// [`ToolbarControls`][controls::ToolbarControl] and communicate other
    /// states.
    #[cfg(feature = "async")]
    pub async fn new_control_sender_async(
        &self,
    ) -> Option<controls::asynchronous::ExtcapControlSender> {
        if let Some(p) = &self.extcap_control_out {
            Some(controls::asynchronous::ExtcapControlSender::new(p).await)
        } else {
            None
        }
    }

    /// Spawn a new channel control reader, which also spawns a thread to
    /// continuously forward control packets from the input fifo to the reader's
    /// channel.
    ///
    /// See the documentations on
    /// [`ChannelExtcapControlReader`][controls::synchronous::ChannelExtcapControlReader] for
    /// more.
    #[cfg(feature = "sync")]
    pub fn spawn_channel_control_reader(
        &self,
    ) -> Option<controls::synchronous::ChannelExtcapControlReader> {
        self.extcap_control_in
            .as_ref()
            .map(|p| controls::synchronous::ChannelExtcapControlReader::spawn(p.to_owned()))
    }

    /// Spawn a new channel control reader, which also spawns a thread to
    /// continuously forward control packets from the input fifo to the reader's
    /// channel.
    ///
    /// See the documentations on
    /// [`ChannelExtcapControlReader`][controls::asynchronous::ChannelExtcapControlReader] for
    /// more.
    #[cfg(feature = "async")]
    pub fn spawn_channel_control_reader_async(
        &self,
    ) -> Option<controls::asynchronous::ChannelExtcapControlReader> {
        self.extcap_control_in
            .as_ref()
            .map(|p| controls::asynchronous::ChannelExtcapControlReader::spawn(p.to_owned()))
    }

    /// Create a new
    /// [`ExtcapControlReader`][controls::synchronous::ExtcapControlReader] for
    /// this capture context. `ExtcapControlReader` reads from the control
    /// pipe given in this context synchronously, and blocks if there are no
    /// incoming control packets waiting to be processed.
    ///
    /// For a higher level, easier to use API, see
    /// [`spawn_channel_control_reader`][Self::spawn_channel_control_reader].
    #[cfg(feature = "sync")]
    pub fn new_control_reader(&self) -> Option<controls::synchronous::ExtcapControlReader> {
        self.extcap_control_in
            .as_ref()
            .map(|p| controls::synchronous::ExtcapControlReader::new(p))
    }

    /// Create a new
    /// [`ExtcapControlReader`][controls::asynchronous::ExtcapControlReader] for
    /// this capture context. `ExtcapControlReader` reads from the control
    /// pipe given in this context synchronously, and blocks if there are no
    /// incoming control packets waiting to be processed.
    ///
    /// For a higher level, easier to use API, see
    /// [`spawn_channel_control_reader`][Self::spawn_channel_control_reader].
    #[cfg(feature = "async")]
    pub async fn new_control_reader_async(
        &self,
    ) -> Option<controls::asynchronous::ExtcapControlReader> {
        if let Some(p) = &self.extcap_control_in {
            Some(controls::asynchronous::ExtcapControlReader::new(p).await)
        } else {
            None
        }
    }

    /// Create an async version of the fifo that is used to write captured
    /// packets to in the PCAP format.
    #[cfg(feature = "async")]
    pub async fn fifo_async(&self) -> tokio::io::Result<tokio::fs::File> {
        tokio::fs::File::create(self.fifo_path).await
    }
}

/// The extcap interface expects certain output "sentences" to stdout to
/// communicate with Wireshark, like
///
/// ```text
/// extcap {version=1.0}{help=Some help url}
/// ```
///
/// This formatter serves as a wrapper to implement that format via the
/// `Display` trait, and the Extcap output can be printed out like this:
///
/// ```
/// use r_extcap::interface::Metadata;
/// # use r_extcap::ExtcapFormatter;
///
/// print!("{}", ExtcapFormatter(&Metadata {
///     version: "1.0".into(),
///     help_url: "Some help url".into(),
///     display_description: "Example extcap".into(),
/// }));
/// // Output: extcap {version=1.0}{help=Some help url}{display=Example extcap}
/// ```
pub struct ExtcapFormatter<'a, T: ?Sized>(pub &'a T)
where
    Self: Display;

/// Elements that has a printable extcap sentence. See the documentation for
/// [`ExtcapFormatter`] for details.
pub trait PrintSentence {
    /// The extcap interface expects certain output "sentences" to stdout to
    /// communicate with Wireshark, like
    ///
    /// ```text
    /// extcap {version=1.0}{help=Some help url}
    /// ```
    ///
    /// This function writes to the formatter `f` in that format.
    fn format_sentence(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;

    /// Prints the extcap sentence to stdout.
    fn print_sentence(&self) {
        print!("{}", ExtcapFormatter(self));
    }
}

impl<'a, T: PrintSentence + ?Sized> Display for ExtcapFormatter<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.format_sentence(f)
    }
}

/// Creates a [`Metadata`] from information in `Cargo.toml`, using the mapping
/// as follows:
///
/// | Metadata field       | Cargo.toml    |
/// |----------------------|---------------|
/// |`version`             | `version`     |
/// |`help_url`            | `homepage`    |
/// |`display_description` | `description` |
#[macro_export]
macro_rules! cargo_metadata {
    () => {
        $crate::interface::Metadata {
            version: env!("CARGO_PKG_VERSION").into(),
            help_url: env!("CARGO_PKG_HOMEPAGE").into(),
            display_description: env!("CARGO_PKG_DESCRIPTION").into(),
        }
    };
}

#[cfg(test)]
mod test {
    use clap::Args;

    use super::ExtcapArgs;

    #[test]
    fn assert_args() {
        let cmd = clap::Command::new("test");
        let augmented_cmd = ExtcapArgs::augment_args(cmd);
        augmented_cmd.debug_assert();
    }
}
