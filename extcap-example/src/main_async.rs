use clap::Parser;
use log::debug;
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink,
};
use r_extcap::{
    controls::asynchronous::{ExtcapControlSender, ExtcapControlSenderTrait},
    controls::*,
    ExtcapStep,
};
use std::{
    io::{stdout, Write},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod common;

use common::*;

async fn control_write_defaults(
    extcap_control: &mut ExtcapControlSender,
    message: &str,
    delay: u8,
    verify: bool,
) -> anyhow::Result<()> {
    CONTROL_MESSAGE
        .set_value(message)
        .send_async(extcap_control)
        .await?;
    CONTROL_BUTTON
        .set_label(&delay.to_string())
        .send_async(extcap_control)
        .await?;
    CONTROL_VERIFY
        .set_checked(verify)
        .send_async(extcap_control)
        .await?;

    for i in 1..16 {
        CONTROL_DELAY
            .add_value(&i.to_string(), Some(&format!("{i} sec")))
            .send_async(extcap_control)
            .await?;
    }
    CONTROL_DELAY
        .remove_value("60")
        .send_async(extcap_control)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
                capture_step.spawn_channel_control_reader_async(),
                capture_step.new_control_sender_async().await,
            );
            if let (Some(control_reader), Some(control_sender)) = &mut controls {
                let packet = control_reader
                    .read_packet()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("Unable to read packet"))?;
                assert_eq!(packet.command, ControlCommand::Initialized);

                CONTROL_LOGGER
                    .clear_and_add_log(format!("Log started at {:?}", SystemTime::now()).into())
                    .send_async(control_sender)
                    .await?;
                control_write_defaults(
                    control_sender,
                    &app_state.message,
                    app_state.delay,
                    app_state.verify,
                )
                .await?;
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
                    if let Some(control_packet) = control_reader.try_read_packet().await {
                        handle_control_packet(&control_packet, control_sender, &mut app_state)
                            .await?;
                    }

                    CONTROL_LOGGER
                        .add_log(format!("Received packet #{counter}").into())
                        .send_async(control_sender)
                        .await?;
                    counter += 1;

                    debug!(
                        "Extcap out control. btn disabled = {}",
                        app_state.button_disabled
                    );

                    if app_state.button_disabled {
                        CONTROL_BUTTON
                            .set_enabled(true)
                            .send_async(control_sender)
                            .await?;
                        control_sender.info_message("Turn action finished.").await?;
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

async fn handle_control_packet(
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
                    control_sender.status_message("Verify changed").await?;
                }
            } else if control_packet.control_number == CONTROL_BUTTON.control_number {
                CONTROL_BUTTON
                    .set_enabled(false)
                    .send_async(control_sender)
                    .await?;
                debug!("Got button control event. button={}", app_state.button);
                app_state.button_disabled = true;
                if app_state.button {
                    CONTROL_BUTTON
                        .set_label("Turn on")
                        .send_async(control_sender)
                        .await?;
                    app_state.button = false;
                    log = Some(String::from("Button turned off"));
                } else {
                    CONTROL_BUTTON
                        .set_label("Turn off")
                        .send_async(control_sender)
                        .await?;
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
        CONTROL_LOGGER
            .add_log(log.into())
            .send_async(control_sender)
            .await?;
    }
    debug!("Read control packet Loop end");
    Ok(())
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
