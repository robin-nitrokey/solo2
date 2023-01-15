#![no_std]

use apdu_dispatch::{
    command::SIZE as ApduCommandSize, response::SIZE as ApduResponseSize, App as ApduApp,
};
use core::{marker::PhantomData, str};
use ctaphid_dispatch::app::App as CtaphidApp;
use trussed::{platform::Syscall, ClientImplementation, Platform, Service};

#[cfg(feature = "admin-app")]
pub use admin_app::Reboot;

pub const CLIENT_COUNT: usize =
    cfg!(feature = "admin-app") as usize +
    cfg!(feature = "fido-authenticator") as usize +
    cfg!(feature = "oauth-authenticator") as usize +
    cfg!(feature = "opcard") as usize +
    cfg!(feature = "provisioner-app") as usize;

pub trait Runner {
    type Syscall: Syscall + Clone;

    #[cfg(feature = "admin-app")]
    type Reboot: Reboot;
    #[cfg(feature = "provisioner-app")]
    type Store: trussed::store::Store;
    #[cfg(feature = "provisioner-app")]
    type Filesystem: trussed::types::LfsStorage + 'static;

    fn uuid(&self) -> [u8; 16];
    fn version(&self) -> u32;
}

pub struct NonPortable<R: Runner> {
    #[cfg(feature = "provisioner-app")]
    pub provisioner: ProvisionerNonPortable<R>,
    pub _marker: PhantomData<R>,
}

type Client<'a, R> = ClientImplementation<'a, (), <R as Runner>::Syscall>;

#[cfg(feature = "admin-app")]
type AdminApp<'a, R> = admin_app::App<Client<'a, R>, <R as Runner>::Reboot>;
#[cfg(feature = "fido-authenticator")]
type FidoApp<'a, R> =
    fido_authenticator::Authenticator<fido_authenticator::Conforming, Client<'a, R>>;
#[cfg(feature = "ndef-app")]
type NdefApp = ndef_app::App<'static>;
#[cfg(feature = "oath-authenticator")]
type OathApp<'a, R> = oath_authenticator::Authenticator<Client<'a, R>>;
#[cfg(feature = "opcard")]
type OpcardApp<'a, R> = opcard::Card<Client<'a, R>>;
#[cfg(feature = "provisioner-app")]
type ProvisionerApp<'a, R> =
    provisioner_app::Provisioner<<R as Runner>::Store, <R as Runner>::Filesystem, Client<'a, R>>;

pub struct Apps<'a, R: Runner> {
    #[cfg(feature = "admin-app")]
    admin: AdminApp<'a, R>,
    #[cfg(feature = "fido-authenticator")]
    fido: FidoApp<'a, R>,
    #[cfg(feature = "ndef-app")]
    ndef: NdefApp,
    #[cfg(feature = "oath-authenticator")]
    oath: OathApp<'a, R>,
    #[cfg(feature = "opcard")]
    opcard: OpcardApp<'a, R>,
    #[cfg(feature = "provisioner-app")]
    provisioner: ProvisionerApp<'a, R>,
}

impl<'a, R: Runner> Apps<'a, R> {
    pub fn new<P: Platform<B = ()>>(
        runner: &R,
        trussed: &mut Service<'a, P, (), CLIENT_COUNT>,
        syscall: &R::Syscall,
        non_portable: NonPortable<R>,
    ) -> Self
    where
        R::Syscall: Clone,
    {
        let NonPortable {
            #[cfg(feature = "provisioner-app")]
            provisioner,
            ..
        } = non_portable;
        Self {
            #[cfg(feature = "admin-app")]
            admin: App::new(runner, trussed, syscall, ()),
            #[cfg(feature = "fido-authenticator")]
            fido: App::new(runner, trussed, syscall, ()),
            #[cfg(feature = "ndef-app")]
            ndef: NdefApp::new(),
            #[cfg(feature = "oath-authenticator")]
            oath: App::new(runner, trussed, syscall, ()),
            #[cfg(feature = "opcard")]
            opcard: App::new(runner, trussed, syscall, ()),
            #[cfg(feature = "provisioner-app")]
            provisioner: App::new(runner, trussed, syscall, provisioner),
        }
    }

    pub fn apdu_dispatch<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut [&mut dyn ApduApp<ApduCommandSize, ApduResponseSize>]) -> T,
    {
        f(&mut [
            #[cfg(feature = "ndef-app")]
            &mut self.ndef,
            #[cfg(feature = "oath-authenticator")]
            &mut self.oath,
            #[cfg(feature = "opcard")]
            &mut self.opcard,
            #[cfg(feature = "fido-authenticator")]
            &mut self.fido,
            #[cfg(feature = "admin-app")]
            &mut self.admin,
            #[cfg(feature = "provisioner-app")]
            &mut self.provisioner,
        ])
    }

    pub fn ctaphid_dispatch<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut [&mut dyn CtaphidApp]) -> T,
    {
        f(&mut [
            #[cfg(feature = "fido-authenticator")]
            &mut self.fido,
            #[cfg(feature = "admin-app")]
            &mut self.admin,
            #[cfg(feature = "oath-authenticator")]
            &mut self.oath,
            #[cfg(feature = "provisioner-app")]
            &mut self.provisioner,
        ])
    }
}

#[cfg(feature = "trussed-usbip")]
impl<'a, R: Runner> trussed_usbip::Apps<Client<'a, R>, (&R, NonPortable<R>)> for Apps<'a, R> {
    fn new(
        make_client: impl Fn(&str) -> Client<'a, R>,
        (runner, data): (&R, NonPortable<R>),
    ) -> Self {
        Self::new(
            runner,
            move |id| {
                let id = core::str::from_utf8(id).expect("invalid client id");
                make_client(id)
            },
            data,
        )
    }

    fn with_ctaphid_apps<T>(&mut self, f: impl FnOnce(&mut [&mut dyn CtaphidApp]) -> T) -> T {
        self.ctaphid_dispatch(f)
    }
}

trait App<'a, R: Runner>: Sized {
    /// non-portable resources needed by this Trussed app
    type NonPortable;

    /// the desired client ID
    const CLIENT_ID: &'static [u8];

    fn new<P: Platform<B = ()>>(
        runner: &R,
        trussed: &mut Service<'a, P, (), CLIENT_COUNT>,
        syscall: &R::Syscall,
        non_portable: Self::NonPortable,
    ) -> Self {
        let id = str::from_utf8(Self::CLIENT_ID).expect("invalid client ID");
        let client = trussed
            .try_new_client(id, syscall.clone())
            .expect("failed to create client");
        Self::with_client(runner, client, non_portable)
    }

    fn with_client(runner: &R, trussed: Client<'a, R>, non_portable: Self::NonPortable) -> Self;
}

#[cfg(feature = "admin-app")]
impl<'a, R: Runner> App<'a, R> for AdminApp<'a, R> {
    const CLIENT_ID: &'static [u8] = b"admin\0";

    type NonPortable = ();

    fn with_client(runner: &R, trussed: Client<'a, R>, _: ()) -> Self {
        Self::new(trussed, runner.uuid(), runner.version())
    }
}

#[cfg(feature = "fido-authenticator")]
impl<'a, R: Runner> App<'a, R> for FidoApp<'a, R> {
    const CLIENT_ID: &'static [u8] = b"fido\0";

    type NonPortable = ();

    fn with_client(_runner: &R, trussed: Client<'a, R>, _: ()) -> Self {
        fido_authenticator::Authenticator::new(
            trussed,
            fido_authenticator::Conforming {},
            fido_authenticator::Config {
                max_msg_size: usbd_ctaphid::constants::MESSAGE_SIZE,
                skip_up_timeout: Some(core::time::Duration::from_secs(2)),
            },
        )
    }
}

#[cfg(feature = "oath-authenticator")]
impl<'a, R: Runner> App<'a, R> for OathApp<'a, R> {
    const CLIENT_ID: &'static [u8] = b"oath\0";

    type NonPortable = ();

    fn with_client(_runner: &R, trussed: Client<'a, R>, _: ()) -> Self {
        Self::new(trussed)
    }
}

#[cfg(feature = "opcard")]
impl<'a, R: Runner> App<'a, R> for OpcardApp<'a, R> {
    const CLIENT_ID: &'static [u8] = b"opcard\0";

    type NonPortable = ();

    fn with_client(runner: &R, trussed: Client<'a, R>, _: ()) -> Self {
        let uuid = runner.uuid();
        let mut options = opcard::Options::default();
        options.serial = [0xa0, 0x20, uuid[0], uuid[1]];
        // TODO: set manufacturer to Nitrokey
        Self::new(trussed, options)
    }
}

#[cfg(feature = "provisioner-app")]
pub struct ProvisionerNonPortable<R: Runner> {
    pub store: R::Store,
    pub stolen_filesystem: &'static mut R::Filesystem,
    pub nfc_powered: bool,
    pub rebooter: fn() -> !,
}

#[cfg(feature = "provisioner-app")]
impl<'a, R: Runner> App<'a, R> for ProvisionerApp<'a, R> {
    const CLIENT_ID: &'static [u8] = b"attn\0";

    type NonPortable = ProvisionerNonPortable<R>;

    fn with_client(runner: &R, trussed: Client<'a, R>, non_portable: Self::NonPortable) -> Self {
        let uuid = runner.uuid();
        Self::new(
            trussed,
            non_portable.store,
            non_portable.stolen_filesystem,
            non_portable.nfc_powered,
            uuid,
            non_portable.rebooter,
        )
    }
}
