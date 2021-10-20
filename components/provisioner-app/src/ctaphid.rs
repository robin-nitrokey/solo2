use trussed::types::LfsStorage;
use trussed::{client, Client as TrussedClient};
use trussed::store::Store;
use ctaphid_dispatch::app::{self as hid, Command as HidCommand, Message};
use ctaphid_dispatch::command::VendorCommand;

use crate::{Command, Provisioner};

const COMMAND_SELECT: VendorCommand = VendorCommand::H70;
const COMMAND_WRITE_BINARY: VendorCommand = VendorCommand::H71;
const COMMAND_WRITE_FILE: VendorCommand = VendorCommand::H72;
const COMMAND_GET_UUID: VendorCommand = VendorCommand::H73;
const COMMAND_GENERATE_P256_KEY: VendorCommand = VendorCommand::H74;
const COMMAND_SAVE_P256_ATTESTATION_CERTIFICATE: VendorCommand = VendorCommand::H75;
const COMMAND_SAVE_T1_INTERMEDIATE_PBULIC_KEY: VendorCommand = VendorCommand::H76;

impl<S, FS, T> hid::App for Provisioner<S, FS, T>
where S: Store,
      FS: 'static + LfsStorage,
      T: TrussedClient + client::X255 + client::HmacSha256,
{
    fn commands(&self) -> &'static [HidCommand] {
        use ctaphid_dispatch::app::Command::Vendor;
        &[
            Vendor(COMMAND_SELECT),
            Vendor(COMMAND_WRITE_BINARY),
            Vendor(COMMAND_WRITE_FILE),
            Vendor(COMMAND_GET_UUID),
            Vendor(COMMAND_GENERATE_P256_KEY),
            Vendor(COMMAND_SAVE_P256_ATTESTATION_CERTIFICATE),
            Vendor(COMMAND_SAVE_T1_INTERMEDIATE_PBULIC_KEY),
        ]
    }

    fn call(&mut self, command: HidCommand, input_data: &Message, response: &mut Message) -> hid::AppResult {
        if let HidCommand::Vendor(command) = command {
            // TODO: more commands
            let command = match command {
                COMMAND_SELECT => Command::Select,
                COMMAND_WRITE_BINARY => Command::WriteBinary,
                COMMAND_WRITE_FILE => Command::WriteFile,
                COMMAND_GET_UUID => Command::GetUuid,
                COMMAND_GENERATE_P256_KEY => Command::GenerateP256Key,
                COMMAND_SAVE_P256_ATTESTATION_CERTIFICATE => Command::SaveP256AttestationCertificate,
                COMMAND_SAVE_T1_INTERMEDIATE_PBULIC_KEY => Command::SaveT1IntermediatePublicKey,
                _ => {
                    return Err(hid::Error::InvalidCommand);
                }
            };
            // TODO: more error types
            self.handle(command, input_data, response)
                .map_err(|_| hid::Error::InvalidLength)
        } else {
            Err(hid::Error::InvalidCommand)
        }
    }
}
