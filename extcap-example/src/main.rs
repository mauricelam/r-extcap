use clap::{Parser, ValueEnum};
use lazy_static::lazy_static;
use log::debug;
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink,
};
use r_extcap::{
    config::*,
    controls::synchronous::{ExtcapControlSender, ExtcapControlSenderTrait},
    controls::*,
    interface::{Dlt, Interface, Metadata},
    ExtcapStep,
};
use std::{
    fmt::Display,
    io::{stdout, Write},
    num::ParseIntError,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

lazy_static! {
    static ref CONFIG_DELAY: IntegerConfig = IntegerConfig::builder()
        .config_number(0)
        .call("delay")
        .display("Time delay")
        .tooltip("Time delay between packages")
        .range(1..=15)
        .default_value(5)
        .build();
    static ref CONFIG_MESSAGE: StringConfig = StringConfig::builder()
        .config_number(1)
        .call("message")
        .display("Message")
        .tooltip("Package message content")
        .required(true)
        .placeholder("Please enter a message here ...")
        .build();
    static ref CONFIG_VERIFY: BooleanConfig = BooleanConfig::builder()
        .config_number(2)
        .call("verify")
        .display("Verify")
        .tooltip("Verify package content")
        .default_value(true)
        .build();
    static ref CONFIG_REMOTE: SelectorConfig = SelectorConfig::builder()
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
    static ref CONFIG_FAKE_IP: StringConfig = StringConfig::builder()
        .config_number(4)
        .call("fake_ip")
        .display("Fake IP Address")
        .tooltip( "Use this ip address as sender")
        .validation(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        .build();
    static ref CONFIG_LTEST: LongConfig = LongConfig::builder()
        .config_number(5)
        .call("ltest")
        .display("Long Test")
        .tooltip("Long Test Value")
        .default_value(123123123123123123)
        .group("Numeric Values")
        .build();
    static ref CONFIG_D1TEST: DoubleConfig = DoubleConfig::builder()
        .config_number(6)
        .call("d1test")
        .display("Double 1 Test")
        .tooltip("Double Test Value")
        .default_value(123.456)
        .group("Numeric Values")
        .build();
    static ref CONFIG_D2TEST: DoubleConfig = DoubleConfig::builder()
        .config_number(7)
        .call("d2test")
        .display("Double 2 Test")
        .tooltip("Double Test Value")
        .default_value(123456.0)
        .group("Numeric Values")
        .build();
    static ref CONFIG_PASSWORD: PasswordConfig = PasswordConfig::builder()
        .config_number(8)
        .call("password")
        .display("Password")
        .tooltip("Package message password")
        .build();
    static ref CONFIG_TIMESTAMP: TimestampConfig = TimestampConfig::builder()
        .config_number(9)
        .call("ts")
        .display("Start Time")
        .tooltip("Capture start time")
        .group("Time / Log")
        .build();
    static ref CONFIG_LOGFILE: FileSelectConfig = FileSelectConfig::builder()
        .config_number(10)
        .call("logfile")
        .display("Log File Test")
        .tooltip("The Log File Test")
        .group("Time / Log")
        .file_extension_filter("Text files (*.txt);;XML files (*.xml)")
        .build();
    static ref CONFIG_RADIO: RadioConfig = RadioConfig::builder()
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
    static ref CONFIG_MULTI: MultiCheckConfig = MultiCheckConfig::builder()
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

    static ref METADATA: Metadata = Metadata {
        help_url: "http://www.wireshark.org".into(),
        display_description: "Rust Example extcap interface".into(),
        ..r_extcap::cargo_metadata!()
    };

    static ref INTERFACE1: Interface = Interface {
        value: "rs-example1".into(),
        display: "Rust Example interface 1 for extcap".into(),
        dlt: Dlt {
            data_link_type: DataLink::USER0,
            name: "USER0".into(),
            display: "Demo Implementation for Extcap".into(),
        },
    };

    static ref INTERFACE2: Interface = Interface {
        value: "rs-example2".into(),
        display: "Rust Example interface 2 for extcap".into(),
        dlt: Dlt {
            data_link_type: DataLink::USER1,
            name: "USER1".into(),
            display: "Demo Implementation for Extcap".into(),
        },
    };

    static ref CONTROL_MESSAGE: StringControl = StringControl {
        control_number: 0,
        display: String::from("Message"),
        tooltip: Some(String::from("Package message content. Must start with a capital letter.")),
        placeholder: Some(String::from("Enter package message content here ...")),
        validation: Some(String::from(r"^[A-Z]+")),
        default_value: None,
    };
    static ref CONTROL_DELAY: SelectorControl = SelectorControl {
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
    static ref CONTROL_VERIFY: BooleanControl = BooleanControl {
        control_number: 2,
        display: String::from("Verify"),
        tooltip: Some(String::from("Verify package control")),
        default_value: false,
    };
    static ref CONTROL_BUTTON: ButtonControl = ButtonControl {
        control_number: 3,
        display: String::from("Turn on"),
        tooltip: Some(String::from("Turn on or off")),
    };
    static ref CONTROL_HELP: HelpButtonControl = HelpButtonControl {
        control_number: 4,
        display: String::from("Help"),
        tooltip: Some(String::from("Show help")),
    };
    static ref CONTROL_RESTORE: RestoreButtonControl = RestoreButtonControl {
        control_number: 5,
        display: String::from("Restore"),
        tooltip: Some(String::from("Restore default values")),
    };
    static ref CONTROL_LOGGER: LoggerControl = LoggerControl {
        control_number: 6,
        display: String::from("Log"),
        tooltip: Some(String::from("Show capture log")),
    };
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Remote {
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

fn control_write_defaults(
    extcap_control: &mut ExtcapControlSender,
    message: &str,
    delay: u8,
    verify: bool,
) -> anyhow::Result<()> {
    CONTROL_MESSAGE.set_value(message).send(extcap_control)?;
    CONTROL_BUTTON
        .set_label(&delay.to_string())
        .send(extcap_control)?;
    CONTROL_VERIFY.set_checked(verify).send(extcap_control)?;

    for i in 1..16 {
        CONTROL_DELAY
            .add_value(&i.to_string(), Some(&format!("{i} sec")))
            .send(extcap_control)?;
    }
    CONTROL_DELAY.remove_value("60").send(extcap_control)?;
    Ok(())
}

#[derive(Debug, Parser)]
pub struct AppArgs {
    #[command(flatten)]
    extcap: r_extcap::ExtcapArgs,

    /// Demonstrates a verification bool flag
    #[arg(long)]
    verify: bool,

    /// Demonstrates an integer variable
    #[arg(long, default_value_t = 5)]
    delay: u8,

    /// Demonstrates a selector choice
    #[arg(long, value_enum, default_value_t = Remote::If1)]
    remote: Remote,

    /// Demonstrates string variable
    #[arg(long, default_value = "Extcap Test")]
    message: String,

    /// Add a fake sender IP address
    #[arg(long, default_value = "127.0.0.1")]
    fake_ip: String,

    /// Capture start time
    #[arg(long, value_parser = |arg: &str| arg.parse().map(std::time::Duration::from_secs))]
    ts: Option<Duration>,

    #[arg(long)]
    ltest: Option<String>,
    #[arg(long)]
    d1test: Option<String>,
    #[arg(long)]
    d2test: Option<String>,
    #[arg(long)]
    radio: Option<String>,
    #[arg(long, value_delimiter = ',')]
    multi: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    debug!("argv: {:?}", std::env::args());
    let args = AppArgs::parse();
    debug!("Args: {args:?}");
    if !args.extcap.capture {
        if let Some(filter) = args.extcap.extcap_capture_filter {
            validate_capture_filter(&filter);
            std::process::exit(0);
        }
    }
    debug!("Running app");
    match args.extcap.run()? {
        ExtcapStep::Interfaces(interfaces_step) => {
            interfaces_step.list_interfaces(
                &METADATA,
                &[&*INTERFACE1, &*INTERFACE2],
                &[
                    &*CONTROL_MESSAGE,
                    &*CONTROL_DELAY,
                    &*CONTROL_VERIFY,
                    &*CONTROL_BUTTON,
                    &*CONTROL_HELP,
                    &*CONTROL_RESTORE,
                    &*CONTROL_LOGGER,
                ],
            );
        }
        ExtcapStep::Dlts(dlts_step) => {
            dlts_step.print_from_interfaces(&[&*INTERFACE1, &*INTERFACE2])?;
        }
        ExtcapStep::Config(config_step) => config_step.list_configs(&[
            &*CONFIG_DELAY,
            &*CONFIG_MESSAGE,
            &*CONFIG_VERIFY,
            &*CONFIG_REMOTE,
            &*CONFIG_FAKE_IP,
            &*CONFIG_LTEST,
            &*CONFIG_D1TEST,
            &*CONFIG_D2TEST,
            &*CONFIG_PASSWORD,
            &*CONFIG_TIMESTAMP,
            &*CONFIG_LOGFILE,
            &*CONFIG_RADIO,
            &*CONFIG_MULTI,
        ]),
        ExtcapStep::ReloadConfig(reload_config_step) => {
            if reload_config_step.config == CONFIG_REMOTE.call {
                reload_config_step.reload_options(&CONFIG_REMOTE)?;
            } else {
                return Err(anyhow::anyhow!(
                    "Unexpected config to reload: {}",
                    reload_config_step.config
                ));
            }
        }
        ExtcapStep::Capture(capture_step) => {
            anyhow::ensure!(args.delay <= 5, "Value for delay {} too high", args.delay);
            let mut app_state = CaptureState {
                initialized: false,
                message: args.message.clone(),
                delay: args.delay,
                verify: args.verify,
                button: false,
                button_disabled: false,
            };
            let mut counter = 1;
            const DATA: &[u8] = b"\
            Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor \
            incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nost \
            rud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis \
            aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugi \
            at nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culp \
            a qui officia deserunt mollit anim id est laborum.";
            let mut controls = (
                capture_step.spawn_channel_control_reader(),
                capture_step.new_control_sender(),
            );
            if let (Some(control_reader), Some(control_sender)) = &mut controls {
                let packet = control_reader.read_packet()?;
                assert_eq!(packet.command, ControlCommand::Initialized);

                CONTROL_LOGGER
                    .clear_and_add_log(format!("Log started at {:?}", SystemTime::now()).into())
                    .send(control_sender)?;
                control_write_defaults(
                    control_sender,
                    &app_state.message,
                    app_state.delay,
                    app_state.verify,
                )?;
            }

            let pcap_header = PcapHeader {
                datalink: DataLink::ETHERNET,
                endianness: pcap_file::Endianness::Big,
                ..Default::default()
            };
            let mut pcap_writer = PcapWriter::with_header(capture_step.fifo, pcap_header)?;
            let mut data_packet = 0;
            let data_total = DATA.len() / 20 + 1;

            for i in 0..usize::MAX {
                if let (Some(control_reader), Some(control_sender)) = &mut controls {
                    if let Some(control_packet) = control_reader.try_read_packet() {
                        handle_control_packet(&control_packet, control_sender, &mut app_state)?;
                    }

                    CONTROL_LOGGER
                        .add_log(format!("Received packet #{counter}").into())
                        .send(control_sender)?;
                    counter += 1;

                    debug!(
                        "Extcap out control. btn disabled = {}",
                        app_state.button_disabled
                    );

                    if app_state.button_disabled {
                        CONTROL_BUTTON.set_enabled(true).send(control_sender)?;
                        control_sender.info_message("Turn action finished.")?;
                        app_state.button_disabled = false;
                    }
                }

                if data_packet * 20 > DATA.len() {
                    data_packet = 0;
                }
                let data_sub = &DATA[data_packet * 20..(data_packet + 1) * 20];
                data_packet += 1;
                let out = create_out_packet(
                    args.remote,
                    data_packet,
                    data_total,
                    data_sub,
                    app_state.message.as_bytes(),
                    app_state.verify,
                );
                let packet = pcap_fake_packet(&out, &args.fake_ip, i)?;

                pcap_writer.write_packet(&PcapPacket::new(
                    SystemTime::now().duration_since(UNIX_EPOCH)?,
                    (packet.len() + 14 + 20) as u32,
                    &packet,
                ))?;
                stdout().flush()?;
                std::thread::sleep(Duration::from_secs(app_state.delay.into()));
            }
        }
    }
    debug!("App run finished");

    Ok(())
}

pub struct CaptureState {
    initialized: bool,
    message: String,
    delay: u8,
    verify: bool,
    button: bool,
    button_disabled: bool,
}

fn handle_control_packet(
    control_packet: &ControlPacket<'_>,
    control_sender: &mut ExtcapControlSender,
    app_state: &mut CaptureState,
) -> anyhow::Result<()> {
    debug!("Read control packet: {control_packet:?}");
    let mut log: Option<String> = None;
    match control_packet.command {
        ControlCommand::Initialized => app_state.initialized = true,
        ControlCommand::Set => {
            if control_packet.control_number == CONTROL_MESSAGE.control_number {
                let msg = String::from_utf8(control_packet.payload.to_vec())?;
                log = Some(format!("Message = {}", msg));
                app_state.message = msg;
            } else if control_packet.control_number == CONTROL_DELAY.control_number {
                app_state.delay =
                    std::str::from_utf8(control_packet.payload.as_ref())?.parse::<u8>()?;
                log = Some(format!("Time delay = {}", app_state.delay));
            } else if control_packet.control_number == CONTROL_VERIFY.control_number {
                // Only read this after initialized
                if app_state.initialized {
                    app_state.verify = control_packet.payload[0] != 0_u8;
                    log = Some(format!("Verify = {:?}", app_state.verify));
                    control_sender.status_message("Verify changed")?;
                }
            } else if control_packet.control_number == CONTROL_BUTTON.control_number {
                CONTROL_BUTTON.set_enabled(false).send(control_sender)?;
                debug!("Got button control event. button={}", app_state.button);
                app_state.button_disabled = true;
                if app_state.button {
                    CONTROL_BUTTON.set_label("Turn on").send(control_sender)?;
                    app_state.button = false;
                    log = Some(String::from("Button turned off"));
                } else {
                    CONTROL_BUTTON.set_label("Turn off").send(control_sender)?;
                    app_state.button = true;
                    log = Some(String::from("Button turned on"));
                }
            } else {
                panic!(
                    "Unexpected control number {}",
                    control_packet.control_number
                )
            }
        }
        _ => panic!("Unexpected control command {:?}", control_packet.command),
    }
    if let Some(log) = log {
        CONTROL_LOGGER.add_log(log.into()).send(control_sender)?;
    }
    debug!("Read control packet Loop end");
    Ok(())
}

fn create_out_packet(
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

fn pcap_fake_packet(
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

fn validate_capture_filter(filter: &str) {
    if filter != "filter" && filter != "valid" {
        println!("Illegal capture filter");
    }
}

#[cfg(test)]
mod test {
    use super::AppArgs;
    use clap::CommandFactory;
    use r_extcap::cargo_metadata;

    #[test]
    fn test_parse() {
        AppArgs::command().debug_assert();
    }

    #[test]
    fn test_default_metadata() {
        // Test to make sure that the default metadata is pulled from the
        // binary's Cargo.toml, not the library's.
        let metadata = cargo_metadata!();
        assert_eq!(metadata.version, "0.1.0");
        assert_eq!(
            metadata.help_url,
            "https://gitlab.com/wireshark/wireshark/-/blob/master/doc/extcap_example.py"
        );
        assert_eq!(
            metadata.display_description,
            "Extcap example program for Rust"
        );
    }
}
