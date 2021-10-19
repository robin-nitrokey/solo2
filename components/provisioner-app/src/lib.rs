//! # Solo 2 provisioner app
//!
//! This is a highly *non-portable* Trussed app.
//!
//! It allows injecting arbitrary binary files at arbitrary paths, e.g., to inject FIDO batch
//! attestation keys.
//! It allows generating Trussed device attestation keys and obtaining their public keys,
//! to then generate and inject attn certs from a given root or intermedidate CA.
//!
//! See `solo2-cli` for usage.
#![no_std]

pub mod apdu;

#[macro_use]
extern crate delog;
generate_macros!();

use trussed::types::LfsStorage;

pub const FILESYSTEM_BOUNDARY: usize = 0x8_0000;

use littlefs2::path::PathBuf;
use trussed::store::{self, Store};
use trussed::{
    syscall,
    client,
    Client as TrussedClient,
    key::{Kind as KeyKind, Key, Flags},
};
use heapless::Vec;

use lpc55_hal as hal;

//
const SOLO_PROVISIONER_AID: [u8; 9] = [ 0xA0, 0x00, 0x00, 0x08, 0x47, 0x01, 0x00, 0x00, 0x01];

const TESTER_FILENAME_ID: [u8; 2] = [0xe1,0x01];
const TESTER_FILE_ID: [u8; 2] = [0xe1,0x02];

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Command {
    Select,
    WriteBinary,
    WriteFile,
    BootToBootrom,
    ReformatFilesystem,
    GetUuid,
    GenerateP256Key,
    GenerateEd255Key,
    GenerateX255Key,
    SaveP256AttestationCertificate,
    SaveEd255AttestationCertificate,
    SaveX255AttestationCertificate,
    SaveT1IntermediatePublicKey,
    #[cfg(feature = "test-attestation")]
    TestAttestation {
        mode: TestAttestationMode,
    }
}

#[cfg(feature = "test-attestation")]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TestAttestationMode {
    P256Sign,
    P256Cert,
    Ed255Sign,
    Ed255Cert,
    X255Agree,
    X255Cert,
    T1Key,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Status {
    NotFound,
    WrongLength,
    NotEnoughMemory,
    IncorrectDataParameter,
}

const FILENAME_T1_PUBLIC: &'static [u8] = b"/attn/pub/00";

const FILENAME_P256_SECRET: &'static [u8] = b"/attn/sec/01";
const FILENAME_ED255_SECRET: &'static [u8] = b"/attn/sec/02";
const FILENAME_X255_SECRET: &'static [u8] = b"/attn/sec/03";

const FILENAME_P256_CERT: &'static [u8] = b"/attn/x5c/01";
const FILENAME_ED255_CERT: &'static [u8] = b"/attn/x5c/02";
const FILENAME_X255_CERT: &'static [u8] = b"/attn/x5c/03";


enum SelectedBuffer {
    Filename,
    File,
}

pub struct Provisioner<S, FS, T>
where S: Store,
      FS: 'static + LfsStorage,
      T: TrussedClient + client::X255 + client::HmacSha256,
{
    trussed: T,

    selected_buffer: SelectedBuffer,
    buffer_filename: Vec<u8, 128>,
    buffer_file_contents: Vec<u8, 8192>,

    store: S,
    stolen_filesystem: &'static mut FS,
    #[allow(dead_code)]
    is_passive: bool,
}

impl<S, FS, T> Provisioner<S, FS, T>
where S: Store,
      FS: 'static + LfsStorage,
      T: TrussedClient + client::X255 + client::HmacSha256,
{
    pub fn new(
        trussed: T,
        store: S,
        stolen_filesystem: &'static mut FS,
        is_passive: bool,
    ) -> Provisioner<S, FS, T> {


        return Self {
            trussed,

            selected_buffer: SelectedBuffer::Filename,
            buffer_filename: Vec::new(),
            buffer_file_contents: Vec::new(),
            store,
            stolen_filesystem,
            is_passive,
        }
    }

    fn handle<const N: usize>(&mut self, command: Command, data: &[u8], reply: &mut Vec<u8, N>) -> Result<(), Status> {
        use Command::*;
        match command {
            Select => self.select(data, reply),
            WriteBinary => {
                match self.selected_buffer {
                    SelectedBuffer::Filename => self.buffer_filename.extend_from_slice(data).unwrap(),
                    SelectedBuffer::File => self.buffer_file_contents.extend_from_slice(data).unwrap(),
                };
                Ok(())
            },
            ReformatFilesystem => {
                // Provide a method to reset the FS.
                info!("Reformatting the FS..");
                littlefs2::fs::Filesystem::format(self.stolen_filesystem)
                    .map_err(|_| Status::NotEnoughMemory)?;
                Ok(())
            }
            WriteFile => {
                if self.buffer_file_contents.len() == 0 || self.buffer_filename.len() == 0 {
                    Err(Status::IncorrectDataParameter)
                } else {
                    // self.buffer_filename.push(0);
                    let _filename = unsafe{ core::str::from_utf8_unchecked(self.buffer_filename.as_slice()) };
                    info!("writing file {} {} bytes", _filename, self.buffer_file_contents.len());
                    // logging::dump_hex(&self.buffer_file_contents, self.buffer_file_contents.len());

                    let res = store::store(
                        self.store,
                        trussed::types::Location::Internal,
                        &PathBuf::from(self.buffer_filename.as_slice()),
                        &self.buffer_file_contents
                    );
                    self.buffer_file_contents.clear();
                    self.buffer_filename.clear();
                    if !res.is_ok() {
                        info!("failed writing file!");
                        Err(Status::NotEnoughMemory)
                    } else {
                        info!("wrote file");
                        Ok(())
                    }
                }
            }
            GenerateP256Key => {
                info!("GenerateP256Key");
                let mut seed = [0u8; 32];
                seed.copy_from_slice(
                    &syscall!(self.trussed.random_bytes(32)).bytes.as_slice()
                );

                let serialized_key = Key {
                    flags: Flags::LOCAL | Flags::SENSITIVE,
                    kind: KeyKind::P256,
                    material: Vec::from_slice(&seed).unwrap(),
                };

                let serialized_bytes = serialized_key.serialize();

                store::store(
                    self.store,
                    trussed::types::Location::Internal,
                    &PathBuf::from(FILENAME_P256_SECRET),
                    &serialized_bytes
                ).map_err(|_| Status::NotEnoughMemory)?;
                info!("stored to {}", core::str::from_utf8(FILENAME_P256_SECRET).unwrap());

                let keypair = nisty::Keypair::generate_patiently(&seed);

                reply.extend_from_slice(keypair.public.as_bytes()).unwrap();
                Ok(())
            }
            GenerateEd255Key => {

                info!("GenerateEd255Key");
                let mut seed = [0u8; 32];
                seed.copy_from_slice(
                    &syscall!(self.trussed.random_bytes(32)).bytes.as_slice()
                );

                let serialized_key = Key {
                    flags: Flags::LOCAL | Flags::SENSITIVE,
                    kind: KeyKind::Ed255,
                    material: Vec::from_slice(&seed).unwrap(),
                };

                // let serialized_key = Key::try_deserialize(&seed[..])
                    // .map_err(|_| Status::WrongLength)?;

                let serialized_bytes = serialized_key.serialize();

                store::store(
                    self.store,
                    trussed::types::Location::Internal,
                    &PathBuf::from(FILENAME_ED255_SECRET),
                    &serialized_bytes
                ).map_err(|_| Status::NotEnoughMemory)?;

                let keypair = salty::Keypair::from(&seed);

                reply.extend_from_slice(keypair.public.as_bytes()).unwrap();
                Ok(())
            },

            GenerateX255Key => {

                info_now!("GenerateX255Key");
                let mut seed = [0u8; 32];
                seed.copy_from_slice(
                    &syscall!(self.trussed.random_bytes(32)).bytes.as_slice()
                );

                let serialized_key = Key {
                    flags: Flags::LOCAL | Flags::SENSITIVE,
                    kind: KeyKind::X255,
                    material: Vec::from_slice(&seed).unwrap(),
                };

                // let serialized_key = Key::try_deserialize(&seed[..])
                    // .map_err(|_| Status::WrongLength)?;

                let serialized_bytes = serialized_key.serialize();

                store::store(
                    self.store,
                    trussed::types::Location::Internal,
                    &PathBuf::from(FILENAME_X255_SECRET),
                    &serialized_bytes
                ).map_err(|_| Status::NotEnoughMemory)?;

                let secret_key = salty::agreement::SecretKey::from_seed(&seed);
                let public_key = salty::agreement::PublicKey::from(&secret_key);

                reply.extend_from_slice(&public_key.to_bytes()).unwrap();
                Ok(())
            },

            SaveP256AttestationCertificate => {
                let secret_path = PathBuf::from(FILENAME_P256_SECRET);
                if !secret_path.exists(&self.store.ifs()) {
                    Err(Status::IncorrectDataParameter)
                } else if data.len() < 100 {
                    // Assuming certs will always be >100 bytes
                    Err(Status::IncorrectDataParameter)
                } else {
                    info!("saving P256 CERT, {} bytes", data.len());
                    store::store(
                        self.store,
                        trussed::types::Location::Internal,
                        &PathBuf::from(FILENAME_P256_CERT),
                        data
                    ).map_err(|_| Status::NotEnoughMemory)?;
                    Ok(())
                }
            },

            SaveEd255AttestationCertificate => {
                let secret_path = PathBuf::from(FILENAME_ED255_SECRET);
                if !secret_path.exists(&self.store.ifs()) {
                    Err(Status::IncorrectDataParameter)
                } else if data.len() < 100 {
                    // Assuming certs will always be >100 bytes
                    Err(Status::IncorrectDataParameter)
                } else {
                    info!("saving ED25519 CERT, {} bytes", data.len());
                    store::store(
                        self.store,
                        trussed::types::Location::Internal,
                        &PathBuf::from(FILENAME_ED255_CERT),
                        data
                    ).map_err(|_| Status::NotEnoughMemory)?;
                    Ok(())
                }
            },

            SaveX255AttestationCertificate => {
                let secret_path = PathBuf::from(FILENAME_X255_SECRET);
                if !secret_path.exists(&self.store.ifs()) {
                    Err(Status::IncorrectDataParameter)
                } else if data.len() < 100 {
                    // Assuming certs will always be >100 bytes
                    Err(Status::IncorrectDataParameter)
                } else {
                    info!("saving X25519 CERT, {} bytes", data.len());
                    store::store(
                        self.store,
                        trussed::types::Location::Internal,
                        &PathBuf::from(FILENAME_X255_CERT),
                        data
                    ).map_err(|_| Status::NotEnoughMemory)?;
                    Ok(())
                }
            },

            SaveT1IntermediatePublicKey => {
                info!("saving T1 INTERMEDIATE PUBLIC KEY, {} bytes", data.len());
                let public_key = data;
                if public_key.len() != 64 {
                    Err(Status::IncorrectDataParameter)
                } else {
                    let serialized_key = Key {
                        flags: Default::default(),
                        kind: KeyKind::P256,
                        material: Vec::from_slice(&public_key).unwrap(),
                    };

                    let serialized_key = serialized_key.serialize();

                    store::store(
                        self.store,
                        trussed::types::Location::Internal,
                        &PathBuf::from(FILENAME_T1_PUBLIC),
                        &serialized_key,
                    ).map_err(|_| Status::NotEnoughMemory)
                }
            },

            #[cfg(feature = "test-attestation")]
            TestAttestation { mode } => {
                // This is only exposed for development and testing.

                use trussed::{
                    types::Mechanism,
                    types::SignatureSerialization,
                    types::KeyId,
                    types::Message,
                    types::StorageAttributes,
                    types::Location,
                    types::KeySerialization,

                };
                use trussed::config::MAX_SIGNATURE_LENGTH;

                let mut challenge = [0u8; 32];
                challenge.copy_from_slice(
                    &syscall!(self.trussed.random_bytes(32)).bytes.as_slice()
                );

                match mode {
                    TestAttestationMode::P256Sign => {
                        let sig: trussed::Bytes<MAX_SIGNATURE_LENGTH> = syscall!(self.trussed.sign(
                            Mechanism::P256,
                            KeyId::from_special(1),
                            &challenge,
                            SignatureSerialization::Asn1Der
                        )).signature;

                        // let sig = Bytes::try_from_slice(&sig);

                        reply.extend_from_slice(&challenge).unwrap();
                        reply.extend_from_slice(&sig).unwrap();
                        Ok(())
                    }
                    TestAttestationMode::P256Cert => {
                        let cert: Message = store::read(self.store,
                            trussed::types::Location::Internal,
                            &PathBuf::from(FILENAME_P256_CERT),
                        ).map_err(|_| Status::NotFound)?;
                        reply.extend_from_slice(&cert).unwrap();
                        Ok(())
                    }
                    TestAttestationMode::Ed255Sign => {

                        let sig: trussed::Bytes<MAX_SIGNATURE_LENGTH> = syscall!(self.trussed.sign(
                            Mechanism::Ed255,
                            KeyId::from_special(2),
                            &challenge,
                            SignatureSerialization::Asn1Der
                        )).signature;

                        // let sig = Bytes::try_from_slice(&sig);

                        reply.extend_from_slice(&challenge).unwrap();
                        reply.extend_from_slice(&sig).unwrap();
                        Ok(())
                    }
                    TestAttestationMode::Ed255Cert => {
                        let cert:Message = store::read(self.store,
                            trussed::types::Location::Internal,
                            &PathBuf::from(FILENAME_ED255_CERT),
                        ).map_err(|_| Status::NotFound)?;
                        reply.extend_from_slice(&cert).unwrap();
                        Ok(())
                    }
                    TestAttestationMode::X255Agree => {

                        syscall!(self.trussed.debug_dump_store());

                        let mut platform_pk_bytes = [0u8; 32];
                        for i in 0 .. 32 {
                            platform_pk_bytes[i] = data[i]
                        }

                        info_now!("1");

                        let platform_kak = syscall!(self.trussed.deserialize_key(
                            Mechanism::X255,
                            // platform sends it's pk as 32 bytes
                            &platform_pk_bytes,
                            KeySerialization::Raw,
                            StorageAttributes::new().set_persistence(Location::Volatile)
                        )).key;
                        info_now!("3");

                        let shared_secret = syscall!(self.trussed.agree_x255(
                            KeyId::from_special(3),
                            platform_kak,
                            Location::Volatile
                        )).shared_secret;
                        info_now!("4");

                        let sig = syscall!(self.trussed.sign_hmacsha256(
                            shared_secret,
                            &challenge,
                        )).signature;

                        info_now!("5");
                        reply.extend_from_slice(&challenge).unwrap();
                        reply.extend_from_slice(&sig).unwrap();
                        Ok(())
                    }
                    TestAttestationMode::X255Cert => {
                        let cert: Message = store::read(self.store,
                            trussed::types::Location::Internal,
                            &PathBuf::from(FILENAME_X255_CERT),
                        ).map_err(|_| Status::NotFound)?;
                        reply.extend_from_slice(&cert).unwrap();
                        Ok(())
                    }
                    TestAttestationMode::T1Key => {
                        let key: Message = store::read(self.store,
                            trussed::types::Location::Internal,
                            &PathBuf::from(FILENAME_T1_PUBLIC),
                        ).map_err(|_| Status::NotFound)?;
                         let key = Key::try_deserialize(&key[..])
                             .map_err(|_| Status::WrongLength)?;
                        reply.extend_from_slice(&key.material).unwrap();
                        Ok(())
                    }
                }

            }

            GetUuid => {
                // Get UUID
                reply.extend_from_slice(&hal::uuid()).unwrap();
                Ok(())
            },
            BootToBootrom => {
                // Boot to bootrom via flash 0 page erase
                use hal::traits::flash::WriteErase;
                let flash = unsafe { hal::peripherals::flash::Flash::steal() }.enabled(
                    &mut unsafe { hal::peripherals::syscon::Syscon::steal()}
                );
                hal::drivers::flash::FlashGordon::new(flash).erase_page(0).ok();
                hal::raw::SCB::sys_reset()
            },

        }
    }

    fn select<const N: usize>(&mut self, data: &[u8], _reply: &mut Vec<u8, N>) -> Result<(), Status> {

        if data.starts_with(&TESTER_FILENAME_ID) {
            info!("select filename");
            self.selected_buffer = SelectedBuffer::Filename;
            Ok(())
        } else if data.starts_with(&TESTER_FILE_ID) {
            info!("select file");
            self.selected_buffer = SelectedBuffer::File;
            Ok(())
        } else {
            info!("unknown ID: {:?}", &data);
            Err(Status::NotFound)
        }

    }

}
