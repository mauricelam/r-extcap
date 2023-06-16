#![allow(unused)]

use clap::{Parser, ValueEnum};
use lazy_static::lazy_static;
use pcap_file::DataLink;
use r_extcap::{
    config::*,
    controls::*,
    interface::{Dlt, Interface, Metadata},
};
use std::{
    fmt::Display,
    num::ParseIntError,
    time::Duration,
};

lazy_static! {
    pub static ref CONFIG_DELAY: IntegerConfig = IntegerConfig::builder()
        .config_number(0)
        .call("delay")
        .display("Time delay")
        .tooltip("Time delay between packages")
        .range(1..=15)
        .default_value(5)
        .build();
    pub static ref CONFIG_MESSAGE: StringConfig = StringConfig::builder()
        .config_number(1)
        .call("message")
        .display("Message")
        .tooltip("Package message content")
        .required(true)
        .placeholder("Please enter a message here ...")
        .build();
    pub static ref CONFIG_VERIFY: BooleanConfig = BooleanConfig::builder()
        .config_number(2)
        .call("verify")
        .display("Verify")
        .tooltip("Verify package content")
        .default_value(true)
        .build();
    pub static ref CONFIG_REMOTE: SelectorConfig = SelectorConfig::builder()
        .config_number(3)
        .call("remote")
        .display("Remote Channel")
        .tooltip("Remote Channel Selector")
        .reload(Reload {
            label: String::from("Load interfaces..."),
            reload_fn: || {
                vec![
                    ConfigOptionValue::builder()
                        .value("if1")
                        .display("Remote Interface 1")
                        .build(),
                    ConfigOptionValue::builder()
                        .value("if2")
                        .display("Remote Interface 2")
                        .default(true)
                        .build(),
                    ConfigOptionValue::builder()
                        .value("if3")
                        .display("Remote Interface 3")
                        .build(),
                    ConfigOptionValue::builder()
                        .value("if4")
                        .display("Remote Interface 4")
                        .build(),
                ]
            }
        })
        .default_options([
            ConfigOptionValue::builder()
                .value("if1")
                .display("Remote1")
                .default(true)
                .build(),
            ConfigOptionValue::builder().value("if2").display("Remote2").build(),
        ])
        .build();
    pub static ref CONFIG_FAKE_IP: StringConfig = StringConfig::builder()
        .config_number(4)
        .call("fake_ip")
        .display("Fake IP Address")
        .tooltip( "Use this ip address as sender")
        .validation(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        .build();
    pub static ref CONFIG_LTEST: LongConfig = LongConfig::builder()
        .config_number(5)
        .call("ltest")
        .display("Long Test")
        .tooltip("Long Test Value")
        .default_value(123123123123123123)
        .group("Numeric Values")
        .build();
    pub static ref CONFIG_D1TEST: DoubleConfig = DoubleConfig::builder()
        .config_number(6)
        .call("d1test")
        .display("Double 1 Test")
        .tooltip("Double Test Value")
        .default_value(123.456)
        .group("Numeric Values")
        .build();
    pub static ref CONFIG_D2TEST: DoubleConfig = DoubleConfig::builder()
        .config_number(7)
        .call("d2test")
        .display("Double 2 Test")
        .tooltip("Double Test Value")
        .default_value(123456.0)
        .group("Numeric Values")
        .build();
    pub static ref CONFIG_PASSWORD: PasswordConfig = PasswordConfig::builder()
        .config_number(8)
        .call("password")
        .display("Password")
        .tooltip("Package message password")
        .build();
    pub static ref CONFIG_TIMESTAMP: TimestampConfig = TimestampConfig::builder()
        .config_number(9)
        .call("ts")
        .display("Start Time")
        .tooltip("Capture start time")
        .group("Time / Log")
        .build();
    pub static ref CONFIG_LOGFILE: FileSelectConfig = FileSelectConfig::builder()
        .config_number(10)
        .call("logfile")
        .display("Log File Test")
        .tooltip("The Log File Test")
        .group("Time / Log")
        .file_extension_filter("Text files (*.txt);;XML files (*.xml)")
        .build();
    pub static ref CONFIG_RADIO: RadioConfig = RadioConfig::builder()
        .config_number(11)
        .call("radio")
        .display("Radio Test")
        .tooltip("Radio Test Value")
        .group("Selection")
        .options([
            ConfigOptionValue::builder().value("r1").display("Radio1").build(),
            ConfigOptionValue::builder()
                .value("r2")
                .display("Radio2")
                .default(true)
                .build(),
        ])
        .build();
    pub static ref CONFIG_MULTI: MultiCheckConfig = MultiCheckConfig::builder()
        .config_number(12)
        .call("multi")
        .display("MultiCheck Test")
        .tooltip("MultiCheck Test Value")
        .group("Selection")
        .options([
            MultiCheckValue::builder()
                .value("m1")
                .display("Checkable Parent 1")
                .children([
                    MultiCheckValue::builder()
                        .value("m1c1")
                        .display("Checkable Child 1")
                        .children([MultiCheckValue::builder()
                            .value("m1c1g1")
                            .display("Uncheckable Grandchild")
                            .enabled(false)
                            .build()])
                        .build(),
                    MultiCheckValue::builder()
                        .value("m1c2")
                        .display("Checkable Child 2")
                        .build(),
                ])
                .build(),
            MultiCheckValue::builder()
                .value("m2")
                .display("Checkable Parent 2")
                .children([
                    MultiCheckValue::builder()
                        .value("m2c1")
                        .display("Checkable Child 1")
                        .children([MultiCheckValue::builder()
                            .value("m2c1g1")
                            .display("Checkable Grandchild")
                            .build()])
                        .build(),
                    MultiCheckValue::builder()
                        .value("m2c2")
                        .display("Uncheckable Child 2")
                        .enabled(false)
                        .children([MultiCheckValue::builder()
                            .value("m2c2g1")
                            .display("Uncheckable Grandchild")
                            .enabled(false)
                            .build()])
                        .build(),
                ])
                .build(),
        ]).build();

    pub static ref METADATA: Metadata = Metadata {
        help_url: "http://www.wireshark.org".into(),
        display_description: "Rust Example extcap interface".into(),
        ..r_extcap::cargo_metadata!()
    };

    pub static ref INTERFACE1: Interface = Interface {
        value: "rs-example1".into(),
        display: "Rust Example interface 1 for extcap".into(),
        dlt: Dlt {
            data_link_type: DataLink::USER0,
            name: "USER0".into(),
            display: "Demo Implementation for Extcap".into(),
        },
    };

    pub static ref INTERFACE2: Interface = Interface {
        value: "rs-example2".into(),
        display: "Rust Example interface 2 for extcap".into(),
        dlt: Dlt {
            data_link_type: DataLink::USER1,
            name: "USER1".into(),
            display: "Demo Implementation for Extcap".into(),
        },
    };

    pub static ref CONTROL_MESSAGE: StringControl = StringControl {
        control_number: 0,
        display: String::from("Message"),
        tooltip: Some(String::from("Package message content. Must start with a capital letter.")),
        placeholder: Some(String::from("Enter package message content here ...")),
        validation: Some(String::from(r"^[A-Z]+")),
        default_value: None,
    };
    pub static ref CONTROL_DELAY: SelectorControl = SelectorControl {
        control_number: 1,
        display: String::from("Time delay"),
        tooltip: Some(String::from("Time delay between packets")),
        options: vec![
            SelectorControlOption::builder().value("1").display("1s").build(),
            SelectorControlOption::builder().value("2").display("2s").build(),
            SelectorControlOption::builder().value("3").display("3s").build(),
            SelectorControlOption::builder().value("4").display("4s").build(),
            SelectorControlOption::builder().value("5").display("5s").default(true).build(),
            SelectorControlOption::builder().value("60").display( "60s").build(),
        ],
    };
    pub static ref CONTROL_VERIFY: BooleanControl = BooleanControl {
        control_number: 2,
        display: String::from("Verify"),
        tooltip: Some(String::from("Verify package control")),
        default_value: false,
    };
    pub static ref CONTROL_BUTTON: ButtonControl = ButtonControl {
        control_number: 3,
        display: String::from("Turn on"),
        tooltip: Some(String::from("Turn on or off")),
    };
    pub static ref CONTROL_HELP: HelpButtonControl = HelpButtonControl {
        control_number: 4,
        display: String::from("Help"),
        tooltip: Some(String::from("Show help")),
    };
    pub static ref CONTROL_RESTORE: RestoreButtonControl = RestoreButtonControl {
        control_number: 5,
        display: String::from("Restore"),
        tooltip: Some(String::from("Restore default values")),
    };
    pub static ref CONTROL_LOGGER: LoggerControl = LoggerControl {
        control_number: 6,
        display: String::from("Log"),
        tooltip: Some(String::from("Show capture log")),
    };
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Remote {
    If1,
    If2,
    If3,
    If4,
}

impl Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_possible_value().unwrap().get_name())
    }
}

#[derive(Debug, Parser)]
pub struct AppArgs {
    #[command(flatten)]
    pub extcap: r_extcap::ExtcapArgs,

    /// Demonstrates a verification bool flag
    #[arg(long)]
    pub verify: bool,

    /// Demonstrates an integer variable
    #[arg(long, default_value_t = 5)]
    pub delay: u8,

    /// Demonstrates a selector choice
    #[arg(long, value_enum, default_value_t = Remote::If1)]
    pub remote: Remote,

    /// Demonstrates string variable
    #[arg(long, default_value = "Extcap Test")]
    pub message: String,

    /// Add a fake sender IP address
    #[arg(long, default_value = "127.0.0.1")]
    pub fake_ip: String,

    /// Capture start time
    #[arg(long, value_parser = |arg: &str| arg.parse().map(std::time::Duration::from_secs))]
    pub ts: Option<Duration>,

    #[arg(long)]
    pub ltest: Option<String>,
    #[arg(long)]
    pub d1test: Option<String>,
    #[arg(long)]
    pub d2test: Option<String>,
    #[arg(long)]
    pub radio: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub multi: Vec<String>,
}

pub struct CaptureState {
    pub initialized: bool,
    pub message: String,
    pub delay: u8,
    pub verify: bool,
    pub button: bool,
    pub button_disabled: bool,
}

pub fn create_out_packet(
    remote: Remote,
    data_packet: usize,
    data_total: usize,
    data_sub: &[u8],
    message: &[u8],
    verify: bool,
) -> Vec<u8> {
    let remote_str = remote.to_string();
    [
        &[remote_str.len() as u8],
        remote_str.as_bytes(),
        &[data_packet as u8],
        &[data_total as u8],
        &[data_sub.len() as u8],
        data_sub,
        &[message.len() as u8],
        message,
        &[u8::from(verify)],
    ]
    .concat()
    .to_vec()
}

pub fn pcap_fake_packet(
    message: &[u8],
    fake_ip: &str,
    iterate_counter: usize,
) -> Result<Vec<u8>, ParseIntError> {
    // ETH
    let (dest_value, src_value) = if iterate_counter % 2 == 0 {
        (0x2900_u16, 0x3400_u16)
    } else {
        (0x3400_u16, 0x2900_u16)
    };

    let result = [
        &dest_value.to_le_bytes()[..],
        &dest_value.to_le_bytes(),
        &dest_value.to_le_bytes(),
        &src_value.to_le_bytes(),
        &src_value.to_le_bytes(),
        &src_value.to_le_bytes(),
        &8_u16.to_le_bytes(), // protocol (ip)
        &[0x45_u8],           // IP version
        &[0],
        &((message.len() + 20) as u16).to_be_bytes(),
        &0_u16.to_be_bytes(), // Identification
        &[0x40],              // Don't fragment
        &[0],                 // Fragment offset
        &[0x40_u8],
        &[0xFE_u8],           // (2 = unspecified)
        &0_u16.to_be_bytes(), // Checksum
        &fake_ip
            .split('.')
            .map(|p| p.parse::<u8>())
            .collect::<Result<Vec<u8>, ParseIntError>>()?,
        &[0x7f, 0x00, 0x00, 0x01], // Dest IP
        message,
    ]
    .concat()
    .to_vec();

    Ok(result)
}

pub fn validate_capture_filter(filter: &str) {
    if filter != "filter" && filter != "valid" {
        println!("Illegal capture filter");
    }
}
