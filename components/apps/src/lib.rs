#![no_std]

use apdu_dispatch::{
    command::SIZE as ApduCommandSize, response::SIZE as ApduResponseSize, App as ApduApp,
};
use core::{marker::PhantomData, str};
use ctaphid_dispatch::app::App as CtaphidApp;
use trussed::{client, platform::Syscall, ClientImplementation, Platform, Service};

#[cfg(feature = "admin-app")]
pub use admin_app::Reboot;

pub const CLIENT_COUNT: usize = cfg!(feature = "admin-app") as usize
    + cfg!(feature = "fido-authenticator") as usize
    + cfg!(feature = "oauth-authenticator") as usize
    + cfg!(feature = "opcard") as usize
    + cfg!(feature = "provisioner-app") as usize;

pub trait Client:
    client::Client
    + client::Aes256Cbc
    + client::Chacha8Poly1305
    + client::Ed255
    + client::HmacSha1
    + client::HmacSha256
    + client::P256
    + client::Sha256
    + client::X255
{
}

impl<C> Client for C where
    C: client::Client
        + client::Aes256Cbc
        + client::Chacha8Poly1305
        + client::Ed255
        + client::HmacSha1
        + client::HmacSha256
        + client::P256
        + client::Sha256
        + client::X255
{
}

pub trait Runner {
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

pub struct Apps<C: Client, R: Runner> {
    _marker: PhantomData<(C, R)>,

    #[cfg(feature = "admin-app")]
    admin: admin_app::App<C, R::Reboot>,

    #[cfg(feature = "fido-authenticator")]
    fido: fido_authenticator::Authenticator<fido_authenticator::Conforming, C>,

    #[cfg(feature = "ndef-app")]
    ndef: ndef_app::App<'static>,

    #[cfg(feature = "oath-authenticator")]
    oath: oath_authenticator::Authenticator<C>,

    #[cfg(feature = "opcard")]
    opcard: opcard::Card<C>,

    #[cfg(feature = "provisioner-app")]
    provisioner: provisioner_app::Provisioner<R::Store, R::Filesystem, C>,
}

impl<C: Client, R: Runner> Apps<C, R> {
    pub fn new(
        runner: &R,
        mut make_client: impl FnMut(&str) -> C,
        non_portable: NonPortable<R>,
    ) -> Self {
        let NonPortable {
            #[cfg(feature = "provisioner-app")]
            provisioner,
            ..
        } = non_portable;
        Self {
            _marker: Default::default(),
            #[cfg(feature = "admin-app")]
            admin: App::new(runner, &mut make_client, ()),
            #[cfg(feature = "fido-authenticator")]
            fido: App::new(runner, &mut make_client, ()),
            #[cfg(feature = "ndef-app")]
            ndef: ndef_app::App::new(),
            #[cfg(feature = "oath-authenticator")]
            oath: App::new(runner, &mut make_client, ()),
            #[cfg(feature = "opcard")]
            opcard: App::new(runner, &mut make_client, ()),
            #[cfg(feature = "provisioner-app")]
            provisioner: App::new(runner, &mut make_client, provisioner),
        }
    }
}

impl<'a, R: Runner, S: Syscall + Default> Apps<ClientImplementation<'a, (), S>, R> {
    pub fn with_service<P, const CLIENT_COUNT: usize>(
        runner: &R,
        trussed: &mut Service<'a, P, (), CLIENT_COUNT>,
        non_portable: NonPortable<R>,
    ) -> Self
    where
        P: Platform<B = ()>,
    {
        Self::new(
            runner,
            |id| {
                trussed
                    .try_new_client(id, S::default())
                    .expect("failed to create client")
            },
            non_portable,
        )
    }
}

impl<C: Client, R: Runner> Apps<C, R> {
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
impl<C: Client, R: Runner> trussed_usbip::Apps<C, (&R, NonPortable<R>)> for Apps<C, R> {
    fn new(
        make_client: impl Fn(&str) -> C,
        (runner, data): (&R, NonPortable<R>),
    ) -> Self {
        Self::new(runner, make_client, data)
    }

    fn with_ctaphid_apps<T>(&mut self, f: impl FnOnce(&mut [&mut dyn CtaphidApp]) -> T) -> T {
        self.ctaphid_dispatch(f)
    }
}

trait App<R: Runner, C: Client>: Sized {
    /// non-portable resources needed by this Trussed app
    type NonPortable;

    /// the desired client ID
    const CLIENT_ID: &'static [u8];

    fn new(
        runner: &R,
        mut make_client: impl FnMut(&str) -> C,
        non_portable: Self::NonPortable,
    ) -> Self {
        let id = str::from_utf8(Self::CLIENT_ID).expect("invalid client ID");
        Self::with_client(runner, make_client(id), non_portable)
    }

    fn with_client(runner: &R, trussed: C, non_portable: Self::NonPortable) -> Self;
}

#[cfg(feature = "admin-app")]
impl<C: Client, R: Runner> App<R, C> for admin_app::App<C, R::Reboot> {
    const CLIENT_ID: &'static [u8] = b"admin\0";

    type NonPortable = ();

    fn with_client(runner: &R, trussed: C, _: ()) -> Self {
        Self::new(trussed, runner.uuid(), runner.version())
    }
}

#[cfg(feature = "fido-authenticator")]
impl<C: Client, R: Runner> App<R, C>
    for fido_authenticator::Authenticator<fido_authenticator::Conforming, C>
{
    const CLIENT_ID: &'static [u8] = b"fido\0";

    type NonPortable = ();

    fn with_client(_runner: &R, trussed: C, _: ()) -> Self {
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
impl<C: Client, R: Runner> App<R, C> for oath_authenticator::Authenticator<C> {
    const CLIENT_ID: &'static [u8] = b"oath\0";

    type NonPortable = ();

    fn with_client(_runner: &R, trussed: C, _: ()) -> Self {
        Self::new(trussed)
    }
}

#[cfg(feature = "opcard")]
impl<C: Client, R: Runner> App<R, C> for opcard::Card<C> {
    const CLIENT_ID: &'static [u8] = b"opcard\0";

    type NonPortable = ();

    fn with_client(runner: &R, trussed: C, _: ()) -> Self {
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
impl<C: Client, R: Runner> App<R, C> for provisioner_app::Provisioner<R::Store, R::Filesystem, C> {
    const CLIENT_ID: &'static [u8] = b"attn\0";

    type NonPortable = ProvisionerNonPortable<R>;

    fn with_client(runner: &R, trussed: C, non_portable: Self::NonPortable) -> Self {
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
