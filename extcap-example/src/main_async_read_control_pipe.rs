use clap::Parser;
use log::debug;
use r_extcap::ExtcapStep;

mod common;

use common::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    debug!("argv: {:?}", std::env::args());
    let args = AppArgs::parse();
    debug!("Args: {args:?}");
    match args.extcap.run()? {
        ExtcapStep::Interfaces(_interfaces_step) => {
            unimplemented!()
        }
        ExtcapStep::Dlts(_dlts_step) => {
            unimplemented!()
        }
        ExtcapStep::Config(_config_step) => {
            unimplemented!()
        }
        ExtcapStep::ReloadConfig(_reload_config_step) => {
            unimplemented!()
        }
        ExtcapStep::Capture(capture_step) => {
            let read_control = async {
                let mut control_reader = capture_step.spawn_channel_control_reader_async().unwrap();
                // Also open the control sender to pretend like we are a real extcap
                let _control_sender = capture_step.new_control_sender_async().await;
                while let Some(_packet) = control_reader.read_packet().await {
                    // Keep reading the packets, make sure this can terminate normally.
                }
                panic!("No more control packets? Should never be reached");
            };
            println!("Waiting for ctrl-C");
            tokio::select! {
                _ = read_control => (),
                _ = tokio::signal::ctrl_c() => (),
            }
            println!("Finished reading control pipe");
        }
    }
    debug!("App run finished");
    Ok(())
}

#[cfg(test)]
mod test {
    use super::AppArgs;
    use clap::CommandFactory;

    #[test]
    fn test_parse() {
        AppArgs::command().debug_assert();
    }
}
