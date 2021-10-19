use core::convert::TryFrom;

use trussed::types::LfsStorage;
use apdu_dispatch::iso7816::{Status as ApduStatus, Instruction};
use trussed::{client, Client as TrussedClient};
use trussed::store::Store;
use apdu_dispatch::{Command as ApduCommand, response, command::SIZE as CommandSize, response::SIZE as ResponseSize};

use crate::{Command, Provisioner, Status};
#[cfg(feature = "test-attestation")]
use crate::TestAttestationMode;

use lpc55_hal as hal;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Instructions {
    WriteFile = 0xbf,

    BootToBootrom = 0x51,
    ReformatFilesystem = 0xbd,
    GetUuid = 0x62,

    GenerateP256Key = 0xbc,
    GenerateEd255Key = 0xbb,
    GenerateX255Key = 0xb7,

    SaveP256AttestationCertificate = 0xba,
    SaveEd255AttestationCertificate = 0xb9,
    SaveX255AttestationCertificate = 0xb6,

    SaveT1IntermediatePublicKey = 0xb5,

    #[cfg(feature = "test-attestation")]
    TestAttestation = 0xb8,
}

impl TryFrom<u8> for Instructions {
    type Error = ApduStatus;

    fn try_from(ins: u8) -> core::result::Result<Self, Self::Error> {
        use Instructions::*;
        Ok(match ins {
            0xbf => WriteFile,

            0x51 => BootToBootrom,
            0xbd => ReformatFilesystem,
            0x62 => GetUuid,

            0xbc => GenerateP256Key,
            0xbb => GenerateEd255Key,
            0xb7 => GenerateX255Key,

            0xba => SaveP256AttestationCertificate,
            0xb9 => SaveEd255AttestationCertificate,
            0xb6 => SaveX255AttestationCertificate,

            0xb5 => SaveT1IntermediatePublicKey,

            #[cfg(feature = "test-attestation")]
            0xb8 => TestAttestation,
            _ => return Err(ApduStatus::FunctionNotSupported),
        })
    }
}

#[cfg(feature = "test-attestation")]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TestAttestationP1 {
    P256Sign = 0,
    P256Cert = 1,
    Ed255Sign= 2,
    Ed255Cert= 3,
    X255Agree = 4,
    X255Cert = 5,
    T1Key = 6,
}

#[cfg(feature = "test-attestation")]
impl From<TestAttestationP1> for TestAttestationMode {
    fn from(value: TestAttestationP1) -> Self {
        match value {
            TestAttestationP1::P256Sign => Self::P256Sign,
            TestAttestationP1::P256Cert => Self::P256Cert,
            TestAttestationP1::Ed255Sign => Self::Ed255Sign,
            TestAttestationP1::Ed255Cert => Self::Ed255Cert,
            TestAttestationP1::X255Agree => Self::X255Agree,
            TestAttestationP1::X255Cert => Self::X255Cert,
            TestAttestationP1::T1Key => Self::T1Key,
        }
    }
}

#[cfg(feature = "test-attestation")]
impl TryFrom<u8> for TestAttestationP1 {
    type Error = ApduStatus;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::P256Sign),
            1 => Ok(Self::P256Cert),
            2 => Ok(Self::Ed255Sign),
            3 => Ok(Self::Ed255Cert),
            4 => Ok(Self::X255Agree),
            5 => Ok(Self::X255Cert),
            6 => Ok(Self::T1Key),
            _ => Err(ApduStatus::FunctionNotSupported),
        }
    }
}

impl<'a> TryFrom<&'a ApduCommand> for Command {
    type Error = ApduStatus;

    fn try_from(apdu_command: &'a ApduCommand) -> Result<Self, Self::Error> {
        match apdu_command.instruction() {
            Instruction::Select => Ok(Command::Select),
                // self.select(apdu_command, reply);
            Instruction::WriteBinary => {
                let _offset: u16 = ((apdu_command.p1 as u16) << 8) | apdu_command.p2 as u16;
                Ok(Command::WriteBinary)
            },
            Instruction::Unknown(ins) => {
                let instruction = Instructions::try_from(ins)?;
                Ok(match instruction {
                    Instructions::WriteFile => Self::WriteFile,
                    Instructions::BootToBootrom => Self::BootToBootrom,
                    Instructions::ReformatFilesystem => Self::ReformatFilesystem,
                    Instructions::GetUuid => Self::GetUuid,
                    Instructions::GenerateP256Key => Self::GenerateP256Key,
                    Instructions::GenerateEd255Key => Self::GenerateEd255Key,
                    Instructions::GenerateX255Key => Self::GenerateX255Key,
                    Instructions::SaveP256AttestationCertificate => Self::SaveP256AttestationCertificate,
                    Instructions::SaveEd255AttestationCertificate => Self::SaveEd255AttestationCertificate,
                    Instructions::SaveX255AttestationCertificate => Self::SaveX255AttestationCertificate,
                    Instructions::SaveT1IntermediatePublicKey => Self::SaveT1IntermediatePublicKey,
                    #[cfg(feature = "test-attestation")]
                    Instructions::TestAttestation => {
                        Self::TestAttestation {
                            mode: TestAttestationP1::try_from(apdu_command.p1)?.into(),
                        }
                    }
                })
            }
            _ => Err(ApduStatus::FunctionNotSupported),
        }
    }
}

impl From<Status> for ApduStatus {
    fn from(status: Status) -> Self {
        match status {
            Status::NotFound => ApduStatus::NotFound,
            Status::WrongLength => ApduStatus::WrongLength,
            Status::NotEnoughMemory => ApduStatus::NotEnoughMemory,
            Status::IncorrectDataParameter => ApduStatus::IncorrectDataParameter,
        }
    }
}

impl<S, FS, T> apdu_dispatch::iso7816::App for Provisioner<S, FS, T>
where S: Store,
      FS: 'static + LfsStorage,
      T: TrussedClient + client::X255 + client::HmacSha256,
{
    fn aid(&self) -> apdu_dispatch::iso7816::Aid {
        apdu_dispatch::iso7816::Aid::new(&crate::SOLO_PROVISIONER_AID)
    }
}


impl<S, FS, T> apdu_dispatch::app::App<CommandSize, ResponseSize> for Provisioner<S, FS, T>
where S: Store,
      FS: 'static + LfsStorage,
      T: TrussedClient + client::X255 + client::HmacSha256,
{
    fn select(&mut self, _apdu: &ApduCommand, reply: &mut response::Data) -> apdu_dispatch::app::Result {
        self.buffer_file_contents.clear();
        self.buffer_filename.clear();
        // For manufacture speed, return uuid on select
        reply.extend_from_slice(&hal::uuid()).unwrap();
        Ok(())
    }

    fn deselect(&mut self) -> () {
    }

    fn call(&mut self, _interface_type: apdu_dispatch::app::Interface, apdu: &ApduCommand, reply: &mut response::Data) -> apdu_dispatch::app::Result {
        let command = Command::try_from(apdu)?;
        self.handle(command, apdu.data(), reply).map_err(From::from)
    }
}
