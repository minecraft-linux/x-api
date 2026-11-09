use std::{
    ffi::{CStr, CString, c_char}, mem::ManuallyDrop, ops::Deref, process::exit, ptr::null, str::FromStr, sync::{Arc, Condvar, Mutex}, thread::sleep, time::Duration,
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc::error::TryRecvError, task::LocalSet};
use xodus::{auth::do_sisu, models::{live::{DAProperty, ExchangeUserTokenOutcome}, packagespc::{PackageDetails, PackageResponse}, secrets::Token, soap}, secrets, tokens::TokenManager, xal::{self, DeviceType, XalAppParameters, XalAuthenticator, oauth2::{AccessToken, EmptyExtraTokenFields}, response}};

use crate::{license::get_license, streaming2::{HttpReaderFactory, Package}};

pub struct Runtime {
    tokio: tokio::runtime::Runtime,
    client: reqwest::Client,
}

#[unsafe(no_mangle)]
pub extern "system" fn initialize() -> *mut Runtime {
    Box::into_raw(Box::new(Runtime {
        tokio: tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap(),
        client: Client::new(),
    }))
}

#[unsafe(no_mangle)]
pub extern "system" fn uninitialize(handle: *mut Runtime) {
    drop(unsafe { Box::from_raw(handle) })
}

#[unsafe(no_mangle)]
pub extern "system" fn fetch_package(
    runtime: *const Runtime,
    url: *const c_char,
    p: u64,
    success: unsafe extern "system" fn(u64, *const Package),
    failure: unsafe extern "system" fn(u64, error: *const c_char),
) {
    let runtime = unsafe { &*runtime };
    let client = runtime.client.clone();
    let url = unsafe { CStr::from_ptr(url) }.to_string_lossy().to_string();
    runtime.tokio.spawn(async move {
        match streaming2::stream_fast(HttpReaderFactory {
            client: client,
            urls: vec![url],
        })
        .await
        {
            Ok(v) => unsafe { success(p, Arc::into_raw(Arc::new(v))) },
            Err(e) => unsafe { failure(p, CString::new(e.to_string()).unwrap().as_ptr()) },
        }
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn destroy_package(package: *const Package) {
    drop(unsafe { Arc::from_raw(package) });
}

// #[unsafe(no_mangle)]
// pub extern "system" fn fetch_license(package: *const Package) {
//     drop(unsafe { Arc::from_raw(package) });
// }

#[derive(Serialize, Deserialize)]
pub struct Device {
    sts: xodus::models::secrets::LegacyToken,
    license: xodus::models::secrets::Device,
}

impl Device {
    fn fill(&self, mgr: &TokenManager) -> Result<(), xodus::tokens::store::TokenStoreError> {
        mgr.save_device_license(&self.license)?;
        mgr.save_device_token(self.sts.key_name.as_ref().cloned().unwrap(), Token::Legacy(self.sts.clone()))
    }
    fn from(mgr: &TokenManager) -> Result<Device, xodus::tokens::store::TokenStoreError> {
        let u = mgr.get_device_license()?;
        let t = mgr.get_device_sts_token()?;
        let Token::Legacy(lt) = t else {
            return Err(xodus::tokens::store::TokenStoreError::NotFound)
        };
        Ok(Device { license: u, sts: lt })
    }
}

#[derive(Serialize, Deserialize)]
pub struct User {
    puid: String,
    username: String,
    sts: xodus::models::secrets::LegacyToken,
}

impl User {
    fn fill(&self, mgr: &TokenManager) -> Result<(), xodus::tokens::store::TokenStoreError> {
        mgr.save_user(&xodus::models::secrets::User{
            puid: self.puid.clone(),
            username: self.username.clone(),
        })?;
        mgr.save_user_token(self.sts.key_name.as_ref().cloned().unwrap_or("http://Passport.NET/STS".to_owned()), Token::Legacy(self.sts.clone()))
    }

    fn from(mgr: &TokenManager) -> Result<User, xodus::tokens::store::TokenStoreError> {
        let u = mgr.get_user()?;
        let t = mgr.get_user_sts_token()?;
        let Token::Legacy(lt) = t else {
            return Err(xodus::tokens::store::TokenStoreError::NotFound)
        };
        Ok(User { puid: u.puid, username: u.username, sts: lt })
    }
}

struct DeviceUser {
    device: Device,
    user: User,
}

impl DeviceUser {
    fn fill(&self, mgr: &TokenManager) -> Result<(), xodus::tokens::store::TokenStoreError> {
        self.device.fill(mgr)?;
        self.user.fill(mgr)
    }

    fn from(mgr: &TokenManager) -> Result<DeviceUser, xodus::tokens::store::TokenStoreError> {
        let d = Device::from(mgr)?;
        let u = User::from(mgr)?;
        Ok(DeviceUser { device: d, user: u })
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn download_all(
    runtime: *const Runtime,
    package: *const Package,
    device: *const Device,
    user: *const User,
    url: *const c_char,
    destination: *const c_char,
    ucontext: u64,
    success: unsafe extern "system" fn(c: u64),
    failure: unsafe extern "system" fn(c: u64, error: *const c_char),
) {
    let runtime = unsafe { &*runtime };
    let tokens = TokenManager::with_memory();
    if !device.is_null() {
        unsafe {&*device}.fill(&tokens).unwrap();
    }
    if !user.is_null() {
        unsafe {&*user}.fill(&tokens).unwrap();
    }
    let package = ManuallyDrop::new(unsafe { Arc::from_raw(package) })
        .deref()
        .clone();
    let client = runtime.client.clone();
    let url = unsafe { CStr::from_ptr(url) }.to_string_lossy().to_string();
    let destination = unsafe { CStr::from_ptr(destination) }
        .to_string_lossy()
        .to_string();
    runtime.tokio.spawn(async move {
        let license = get_license(
            &client,
            &tokens,
            package.xvd_header.vduid.to_string(),
            "neutral".to_owned(),
        )
        .await;
        if let Err(err) = license {
            let cerr = CString::from_str(&err).unwrap();
            unsafe { failure(ucontext, cerr.as_ptr()) };
            return;
        }
        let (key, game_splicense) = license.unwrap();
        if game_splicense.content_keys.len() != 1 {
            unsafe { failure(ucontext, c"unexpected number of content keys".as_ptr()) };
            return;
        }
        let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
            unsafe { failure(ucontext, c"E-1343".as_ptr()) };
            return;
        };

        let full_key = match content_key.unpack(&key) {
            Ok(v) => v,
            Err(e) => {
                let cerr = CString::from_str(&format!("failed to unpack {}", e.to_string())).unwrap();
                unsafe { failure(ucontext, cerr.as_ptr()) };
                return;
            }
        };

        match package
            .download_all(
                HttpReaderFactory {
                    client: client,
                    urls: vec![url],
                },
                destination,
                Some(*full_key),
            )
            .await
        {
            Ok(_) => unsafe { success(ucontext) },
            Err(e) => unsafe { failure(ucontext, CString::new(e.to_string()).unwrap().as_ptr()) },
        }
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn get_device_key_chain() -> *const Device {
    secrets::init_secrets().expect("Unable to initialize credentials");
    let def_store = TokenManager::with_keychain_and_memory();
    Device::from(&def_store).map_or_default(|d|Arc::into_raw(Arc::new(d)))
}

#[unsafe(no_mangle)]
pub extern "system" fn device_export(user: *const Device, context: u64, callback: unsafe extern "system" fn(context: u64, serialized: *const c_char)) {
    let serialized = CString::new(serde_json::to_string(unsafe {
        &*user
    }).unwrap()).unwrap();
    unsafe { callback(context, serialized.as_ptr()) };
}

#[unsafe(no_mangle)]
pub extern "system" fn device_import(serialized: *const c_char) -> *const Device  {
    let user = serde_json::from_str(&unsafe { CStr::from_ptr(serialized) }.to_string_lossy()).unwrap();
    Arc::into_raw(Arc::new(user))
}

#[unsafe(no_mangle)]
pub extern "system" fn get_user_key_chain() -> *const User {
    secrets::init_secrets().expect("Unable to initialize credentials");
    let def_store = TokenManager::with_keychain_and_memory();
    User::from(&def_store).map_or_default(|d|Arc::into_raw(Arc::new(d)))
}

#[unsafe(no_mangle)]
pub extern "system" fn user_export(user: *const User, context: u64, callback: unsafe extern "system" fn(context: u64, serialized: *const c_char)) {
    let serialized = CString::new(serde_json::to_string(unsafe {
        &*user
    }).unwrap()).unwrap();
    unsafe { callback(context, serialized.as_ptr()) };
}

#[unsafe(no_mangle)]
pub extern "system" fn user_import(serialized: *const c_char) -> *const User  {
    let user = serde_json::from_str(&unsafe { CStr::from_ptr(serialized) }.to_string_lossy()).unwrap();
    Arc::into_raw(Arc::new(user))
}

const CLIENT_ID: &str = "0000000040159362";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0&clientid=0000000040159362&ssoappgroup=none";

pub struct UserWebviewContext {
    sender: tokio::sync::mpsc::Sender<Option<DAProperty>>
}

#[unsafe(no_mangle)]
pub extern "system" fn user_webview_submit(context: *const UserWebviewContext, payload: *const c_char) {
    let context = unsafe {
        &*context
    };
    if payload.is_null() {
        context.sender.blocking_send(None).unwrap();
        return;
    }
    let p = unsafe { CStr::from_ptr(payload) }.to_string_lossy().to_string();
    println!("SERVERDATA {}", p);
    context.sender.blocking_send(match serde_json::from_str(&p) {
        Ok(v) => Some(v),
        Err(e) => {
            println!("Error: {}", e);
            None
        },
    }).unwrap();
}

#[unsafe(no_mangle)]
pub extern "system" fn user_refresh(runtime: *const Runtime, device: *const Device, user: *const User, ucontext: u64, webview: unsafe extern "system" fn(u64, context: *const UserWebviewContext, start_url: *const c_char, end_url: *const c_char), success: unsafe extern "system" fn(u64, *const User),
    failure: unsafe extern "system" fn(u64, error: *const c_char)) {
    let tokens = TokenManager::with_memory();
    unsafe {&*device}.fill(&tokens).unwrap();
    if !user.is_null() {
        unsafe {&*user}.fill(&tokens).unwrap();
    }

    let token = tokens.get_device_sts_token().unwrap();
    let Token::Legacy(token) = token else {
        unsafe { failure(ucontext, c"Invalid STS token".as_ptr()) };
        return;
    };
    let device_token = token.clone();
    let client_id = CLIENT_ID.to_string().clone();
    let username = "USERNAME".to_owned();
    let mut user_token = if let Ok(Token::Legacy(token)) = tokens.get_user_sts_token() {
        token
    } else { xodus::models::secrets::LegacyToken {
        key_name: Some("http://Passport.NET/STS".to_owned()),
        token: "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"devicesoftware\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"></EncryptionMethod><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyName>http://Passport.NET/STS</ds:KeyName></ds:KeyInfo><CipherData><CipherValue></CipherValue></CipherData></EncryptedData>".to_owned(),
        binary_secret: None,
        tpm_key: None,
        lifetime: soap::Timestamp {
            id: None,
            created: "".to_owned(),
            expires: "".to_owned(),
        },
    }};

    let mut scopes = vec![(
        USER_AUTH_SCOPE.to_string(),
        Some(soap::PolicyReference::token_broker()),
    )];

    // scopes.push(("http://Passport.NET/tb".to_string(), None));

    let runtime = unsafe { &*runtime };
    let client = runtime.client.clone();

    runtime.tokio.spawn(async move {
        let mut user_data = None;
        loop {
            let outcome = match xodus::api::live::exchange_user_token(
                &client,
                user_token.clone(),
                username.clone(),
                device_token.clone(),
                None,
                None,
                client_id.clone(),
                &scopes,
            )
            .await {
                Ok(v) => v,
                Err(_) => {
                    let (s, mut r) = tokio::sync::mpsc::channel(1);
                    let context = Box::pin(UserWebviewContext {
                        sender: s,
                    });
                    unsafe { webview(ucontext, context.as_ref().get_ref(),
                        null(),
                        c"https://login.live.com/ppsecure/post.srf".as_ptr(),
                    ) };
                    let Some(rdata) = r.recv().await.unwrap()  else {
                        unsafe { failure(ucontext, c"webview dismissed".as_ptr()) };
                        break;
                    };
                    user_token.token = rdata.da_token.clone();
                    user_token.lifetime.created = rdata.da_start_time.clone();
                    user_token.lifetime.expires = rdata.da_expires.clone();
                    user_data = Some(rdata);
                    continue;
                },
            };

            let final_token: Token = match outcome {
                ExchangeUserTokenOutcome::Fault(Some(pp)) => {
                    println!("login url: {}", pp.inline_auth_url.as_deref().unwrap());
                    println!(
                        "login end url: {}",
                        pp.inline_end_auth_url.as_deref().unwrap()
                    );
                    let (s, mut r) = tokio::sync::mpsc::channel(1);
                    let context = Box::pin(UserWebviewContext {
                        sender: s,
                    });
                    let login_url = CString::from_str(pp.inline_auth_url.as_deref().unwrap()).unwrap();
                    unsafe { webview(ucontext, context.as_ref().get_ref(),
                        login_url.as_ptr(),
                        c"https://login.live.com/ppsecure/post.srf".as_ptr(),
                    ) };
                    let Some(rdata) = r.recv().await.unwrap()  else {
                        unsafe { failure(ucontext, c"webview dismissed".as_ptr()) };
                        break;
                    };
                    user_token.token = rdata.da_token.clone();
                    user_token.lifetime.created = rdata.da_start_time.clone();
                    user_token.lifetime.expires = rdata.da_expires.clone();
                    user_data = Some(rdata);
                    continue;
                }
                ExchangeUserTokenOutcome::Fault(_) => {
                    unreachable!();
                }
                ExchangeUserTokenOutcome::Issued(
                    soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
                ) => {
                    let token = collection.security_tokens.remove(0);
                    for token in collection.security_tokens {
                        let address = token
                            .applies_to
                            .endpoint_reference
                            .address
                            .clone();
                        let token = token.into();
                        let address = if let Token::Legacy(legacy) = &token {
                            legacy.key_name.clone().unwrap_or(address)
                        } else {
                            address
                        };
                        tokens.save_user_token(address, token).unwrap();
                    }
                    token.into()
                }
                ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
                    token,
                )) => (*token).into(),
                _ => unreachable!("Only responses are handled"),
            };

            match final_token {
                Token::Legacy(legacy_token) => println!("legacy {}", legacy_token.token),
                Token::Compact(c) => println!("compact {c}"),
            }

            tokens.save_user(&xodus::models::secrets::User{
                puid: user_data.as_ref().unwrap().puid.clone(),
                username: user_data.as_ref().unwrap().username.clone(),
            }).unwrap();
            tokens.save_user_token("http://Passport.NET/STS".to_string(), Token::Legacy(user_token)).unwrap();

            let result = User::from(&tokens).map_or_default(|d|Arc::into_raw(Arc::new(d)));

            unsafe { success(ucontext, result) };
            return;
        }
    });
}

#[repr(C)]
pub struct CProgress {
    cur: usize,
    total: usize,
}

#[unsafe(no_mangle)]
pub extern "system" fn get_progress_all(package: *const Package) -> CProgress {
    let package = unsafe { &*package };
    let Ok((c, t)) = package.get_progress(vec![]) else {
        return CProgress { cur: 0, total: 0 };
    };
    CProgress { cur: c, total: t }
}

#[unsafe(no_mangle)]
pub extern "system" fn package_dump(package: *const Package) {
    (unsafe { &*package }).dump();
}

use std::collections::HashMap;
use std::os::fd::{AsFd, IntoRawFd};
use std::path::Path;
use std::process::ExitCode;

use msixvc::layout::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::{File, OpenOptions};
use tokio::process::Command;

#[cfg(target_os = "linux")]
fn make_temp_file(_folder: &str) -> std::io::Result<std::fs::File> {
    let fd = memfd_create("xodus", MemfdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn make_temp_file(folder: &str) -> std::io::Result<std::fs::File> {
    if folder.is_empty() {
        tempfile()
    } else {
        tempfile_in(folder)
    }
}

#[cfg(target_os = "macos")]
async fn prepare(lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    let disk_size: u64 = lfiles
        .iter()
        .filter(|f| f.1.keep_encrypted)
        .map(|f| f.1.length + 4 * PAGE_SIZE as u64)
        .reduce(|o, s| o + s)
        .unwrap();

    let device_s = String::from_utf8(
        Command::new("/usr/bin/hdiutil")
            .arg("attach")
            .arg("-nomount")
            .arg(format!("ram://{}", disk_size.div_ceil(256)))
            .output()
            .await
            .unwrap()
            .stdout,
    )
    .unwrap();

    let device = device_s.trim();

    let vol = uuid::Uuid::new_v4().to_string();

    let fmt = Command::new("/sbin/newfs_hfs")
        .arg("-v")
        .arg(vol)
        .arg(device)
        .status()
        .await
        .unwrap();
    assert!(fmt.success());

    let mount_dir_obj = tempdir().unwrap();
    let mount_dir = mount_dir_obj.path().to_str().unwrap();

    let mnt = Command::new("/sbin/mount")
        .arg("-t")
        .arg("hfs")
        .arg("-o")
        .arg("nobrowse")
        .arg("-v")
        .arg(device)
        .arg(mount_dir)
        .status()
        .await
        .unwrap();
    assert!(mnt.success());
    let mount_dir_cl = mount_dir.to_string();
    let device_cl = device.to_string();
    (
        async move || {
            let mnt = Command::new("/sbin/umount")
                .arg("-f")
                .arg(mount_dir_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());

            let mnt = Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg("-force")
                .arg(&device_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());
        },
        mount_dir.to_owned(),
    )
}

#[cfg(not(target_os = "macos"))]
async fn prepare(_lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    (async || {}, "".to_owned())
}

#[derive(Deserialize, Debug)]
pub struct Executable {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "TargetDeviceFamily")]
    pub target_device_family: String,
    #[serde(rename = "Id")]
    pub id: String,    
}

#[derive(Deserialize, Debug)]
pub struct ExecutableList {
    pub executables: Vec<Executable>
}

#[derive(Deserialize, Debug)]
pub struct Game {
    #[serde(rename = "StoreId")]
    pub store_id: String,
    #[serde(rename = "TitleId")]
    pub title_id: String,
    #[serde(rename = "MSAAppId")]
    pub msa_app_id: Option<String>,
    #[serde(rename = "ExecutableList")]
    pub executable_list: ExecutableList
}

#[unsafe(no_mangle)]
pub extern "system" fn get_game_versions(runtime: *const Runtime, device: *const Device, content_id: *const c_char, version: *const c_char, context: u64, success: unsafe extern "system" fn(context: u64, version: *const c_char), failure: unsafe extern "system" fn(context: u64, version: *const c_char) ) {
    let runtime = unsafe { &*runtime };
    let client = runtime.client.clone();
    let tokens = TokenManager::with_memory();
    if !device.is_null() {
        unsafe {&*device}.fill(&tokens).unwrap();
    }
    let user = get_user_key_chain();
    if !user.is_null() {
        unsafe {&*user}.fill(&tokens).unwrap();
    }
    let content_id = unsafe { CStr::from_ptr(content_id) }.to_string_lossy().to_string();
    let version = if version.is_null() { None } else {
        Some(unsafe { CStr::from_ptr(version) }.to_string_lossy().to_string())
    };
    runtime.tokio.spawn(async move {
        // match get_packages_ex(&client, &tokens, content_id, version).await.map(|v|serde_json::to_string(&v).ok().map(CString::new)) {
        match get_packages_ex(&client, &tokens, content_id, version).await.map(|v|CString::new(v)) {
            Ok(Ok(v)) => unsafe { success(context, v.as_ptr()) },
            Err(e) => unsafe { failure(context, CString::new(e.to_string()).ok().unwrap_or(c"Unknown error".to_owned()).as_ptr()) },
            _ => unsafe { failure(context, c"Unknown error".as_ptr()) },
        }
    });
}

use xodus::XBOX_LIVE_PACKAGES_PC;
pub async fn get_packages_ex(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    version: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let Token::Legacy(device_token) = tokens.get_device_sts_token()? else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };
    let device_token_resp: soap::RequestSecurityTokenResponse =
        xodus::api::live::exchange_device_token(
            client,
            device_token.clone(),
            "000000004424da1f".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0&clientid=000000004424da1f".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await?;

    let Token::Compact(ms_device_token) = device_token_resp.into() else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    // let Token::Legacy(token) = tokens.get_user_sts_token()? else {
    //     return Err(Box::new(std::io::Error::new(
    //         std::io::ErrorKind::BrokenPipe,
    //         "error",
    //     )));
    // };
    // let scope = "xboxlive.signin";

    // let user_token = xodus::api::live::exchange_user_token(
    //     client,
    //     token,
    //     "USERNAME".to_string(),
    //     device_token,
    //     None,
    //     Some("Silent".to_string()),
    //     "000000004424da1f".to_string(),
    //     &[
    //         (
    //             format!("scope={scope}&api-version=2.0&clientid={}&ssoappgroup=none", "000000004424da1f"),
    //             Some(soap::PolicyReference::token_broker()),
    //         ),
    //         ("http://Passport.NET/tb".to_string(), None),
    //     ],
    // )
    // .await?;

    // let ExchangeUserTokenOutcome::Issued(
    //     soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
    // ) = user_token
    // else {
    //     return Err(Box::new(std::io::Error::new(
    //         std::io::ErrorKind::BrokenPipe,
    //         "error",
    //     )));
    // };

    // if let Some(sts) = collection.security_tokens.pop() {
    //     let address = sts.applies_to.endpoint_reference.address.clone();
    //     let sts: Token = sts.into();
    //     let address = if let Token::Legacy(legacy) = &sts {
    //         legacy.key_name.clone().unwrap_or(address)
    //     } else {
    //         address
    //     };
    //     if let Err(err) = tokens.save_user_token(address, sts) {
    //         // tracing::warn!("Failed to persist refreshed STS token: {err}");
    //     }
    // }
    // let token: soap::RequestSecurityTokenResponse = collection.security_tokens.remove(0);
    // let token: Token = token.into();
    // let user_token = match token {
    //     Token::Compact(t) => t,
    //     _ => {
    //         return Err(Box::new(std::io::Error::new(
    //             std::io::ErrorKind::BrokenPipe,
    //             "error",
    //         )));
    //     }
    // };


    let mut auth = XalAuthenticator::new(
        XalAppParameters {
            client_id: CLIENT_ID.to_owned(),
            title_id: None,
            auth_scopes: vec![],
            redirect_uri: None,
            client_secret: None,
        },
        xal::XalClientParameters {
            user_agent: "XAL GRTS 2025.11.20251105.000".to_string(),
            device_type: DeviceType::WIN32,
            client_version: "10.0.22621".to_string(),
            query_display: String::new(),
        },
        "RETAIL".to_owned(),
    );

    let data = auth
        .get_device_token_rps(ms_device_token.to_owned())
        .await?;

    // let utoken = auth.get_user_token(&response::WindowsLiveTokens::new(AccessToken::new(user_token), xal::oauth2::basic::BasicTokenType::Bearer, EmptyExtraTokenFields{}), xal::AccessTokenPrefix::D).await?;
    //Some(&utoken)
    let token = auth.get_xsts_token(Some(&data), None, None, "http://update.xboxlive.com").await?;

    let response = client
        .get(version.map_or_else(
            || format!("{XBOX_LIVE_PACKAGES_PC}/GetBasePackage/{content_id}"),
            |version| {
                format!("{XBOX_LIVE_PACKAGES_PC}/GetSpecificBasePackage/{content_id}/{version}")
            },
        ))
        .header("x-xbl-contract-version", "3")
        .header(
            "Authorization",
            format!("XBL3.0 x={};{}", "-", token.token),
        )
        .send()
        .await?;

    // let res: PackageResponse = response.json().await?;

    // let PackageResponse::Found(package) = res else {
    //     return Err(Box::new(std::io::Error::other(
    //         "Package was not found, is it owned by the user?",
    //     )));
    // };
    // Ok(package)
    let r = response.text().await?;
    Ok(r)
}


#[unsafe(no_mangle)]
pub extern "system" fn run_game(runtime: *const Runtime, device: *const Device, user: *const User, source: *const c_char, wine: *const c_char) -> i32 {
    let runtime = unsafe { &*runtime };
    let client = runtime.client.clone();
    let tokens = TokenManager::with_memory();
    if !device.is_null() {
        unsafe {&*device}.fill(&tokens).unwrap();
    }
    if !user.is_null() {
        unsafe {&*user}.fill(&tokens).unwrap();
    }

    let source = unsafe { CStr::from_ptr(source).to_string_lossy().to_string() };
    let wine = unsafe { CStr::from_ptr(wine).to_string_lossy().to_string() };

    let r = runtime.tokio.block_on(async move {
        run(&client, &tokens, source, wine, None, None).await
    });
    if r == ExitCode::SUCCESS {
        0
    } else {
        1
    }
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    wine: String,
    exe: Option<String>,
    market: Option<String>,
) -> ExitCode {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let out_absolute = std::fs::canonicalize(out).unwrap();
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .unwrap();

    let xvd = XvdFile::parse(&mut file).await.expect("no err");

    let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
            lfiles = sfiles;
        }
    }

    // Classic files
    if lfiles.is_empty() {
        let sfiles = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
            .expect("ok");
        for (n, sfile) in &sfiles {
            if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        lfiles.extend(sfiles);
    }

    let license = get_license(
        client,
        tokens,
        xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return ExitCode::FAILURE;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return ExitCode::FAILURE;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let mut fds = vec![];

    let (cleanup, mount_dir) = prepare(&lfiles).await;

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let mut game_exe = File::from_std(make_temp_file(&mount_dir).unwrap());

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        match xvd.mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
            .await {
                Ok(_) => (),
                Err(_) => {
                    fds.push((file.0, 0));
                    continue},
            }

        let stdf = game_exe.into_std().await;

        let mut flags = fcntl_getfd(stdf.as_fd()).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(stdf.as_fd(), flags).unwrap();

        fds.push((file.0, stdf.into_raw_fd()));
    }

    let mut env_value = String::new();
    let prefix = out_absolute.to_string_lossy();
    let prefix = prefix.trim_end_matches('/');

    let mut nt_entry = None;

    for fd in fds {
        let suffix = fd.0.replace("\\", "/");
        let suffix = suffix.trim_start_matches('/');
        let unix_path = format!("{}/{}", prefix, suffix);
        if let Some(exe) = &exe {
            if exe == fd.0 {
                nt_entry = Some(unix_path)
            }
        } else if nt_entry.is_none() {
            nt_entry = Some(unix_path)
        }
        if fd.1 == 0 {
            continue;
        }
        println!("{suffix}");

        if !env_value.is_empty() {
            env_value.push('|');
        }
        env_value.push_str(&format!("{}:{}/{}", fd.1, prefix, suffix))
    }

    let Some(nt_entry) = nt_entry else {
        eprintln!("Could not find .exe");
        return ExitCode::FAILURE;
    };

    let mut wn = Command::new(wine)
        .arg(nt_entry)
        .env("WINE_EXE_FILE_MAP", env_value)
        .spawn()
        .unwrap();

    let pid = wn.id().unwrap();

    ctrlc::set_handler(move || {
        if pid > 0 {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
        }
    })
    .expect("failed to install Ctrl+C handler");

    let status = wn.wait().await.unwrap();

    // cleanup().await;
            // 1. Create a LocalSet context tracker
    // let local = LocalSet::new();
    // 2. Run your non-Send asynchronous tasks inside the LocalSet loop
    // local.run_until(async move{
    //     // tokio::task::spawn_local handles non-Send futures safely!
    //     let handle = tokio::task::spawn_local(async move {
    //         cleanup().await;
    //     });

    //     handle.await.unwrap()
    // }).await;

    ExitCode::from(status.code().map(|c| c as u8).unwrap_or(0))
}

pub mod streaming2;
mod license;

unsafe extern "system" fn test_success(d: u64, pkg: *const Package) {
    package_dump(pkg);
    // let dev = get_device_key_chain();
    // let user = get_user_key_chain();
    // download_all(runtime, package, device, user, url, destination, success, failure);

    // unsafe { Arc::from_raw(d as *const (Condvar, Mutex<()>) ) }.0.notify_all();
    unsafe { Arc::from_raw(d as *const tokio::sync::mpsc::Sender<*const Package> ) }.try_send(pkg).unwrap();

}

unsafe extern "system" fn test_failure(d: u64, msg: *const c_char) {
    let url = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    println!("{}", url);
    // unsafe { Arc::from_raw(d as *const (Condvar, Mutex<()>) ) }.0.notify_all();
    unsafe { Arc::from_raw(d as *const tokio::sync::mpsc::Sender<*const Package> ) }.try_send(null()).unwrap();
}

#[unsafe(no_mangle)]
pub extern "system" fn demo() {
    let r = Arc::new((Condvar::new(), Mutex::new(())));

    let rt = initialize();
    fetch_package(rt, c"http://assets2.xboxlive.com/14/aa14a80d-58ae-492a-8a48-b9e5ae421187/1d4dfd7a-d46b-4eaa-b2d2-d855c95bbbd1/1.75.0.0.119fa092-373a-4e87-a067-e3c4f7efa433/RawFury.StarTrucker_1.75.0.0_x64__9s0pnehqffj7t.msixvc".as_ptr(), Arc::into_raw(r.clone()) as u64, test_success, test_failure);

    let g = r.1.lock().unwrap();
    let g = r.0.wait(g).unwrap();
    drop(g);
}

unsafe extern "system" fn test_webview(c: u64, wc: *const UserWebviewContext, start: *const i8, end: *const i8) {
    println!("{}", unsafe { CStr::from_ptr(start).to_string_lossy() });
    user_webview_submit(wc, null());
}

unsafe extern "system" fn test_webview_success(c: u64, u: *const User) {

}
unsafe extern "system" fn test_webview_failure(c: u64, error: *const c_char) {

}

unsafe extern "system" fn test_success2(d: u64) {
    unsafe { Arc::from_raw(d as *const tokio::sync::mpsc::Sender<Result<(), String>> ) }.try_send(Ok(())).unwrap();
}

unsafe extern "system" fn test_failure2(d: u64, msg: *const c_char) {
    let url = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    println!("{}", url);
    unsafe { Arc::from_raw(d as *const tokio::sync::mpsc::Sender<Result<(), String>> ) }.try_send(Err(url)).unwrap();
}


#[test]
fn test() {
    // let r = Arc::new((Condvar::new(), Mutex::new(())));
    let (r, mut t) = tokio::sync::mpsc::channel(1);
    let r = Arc::new(r);

    let rt = initialize();
    fetch_package(rt, c"http://assets2.xboxlive.com/14/aa14a80d-58ae-492a-8a48-b9e5ae421187/1d4dfd7a-d46b-4eaa-b2d2-d855c95bbbd1/1.75.0.0.119fa092-373a-4e87-a067-e3c4f7efa433/RawFury.StarTrucker_1.75.0.0_x64__9s0pnehqffj7t.msixvc".as_ptr(), Arc::into_raw(r.clone()) as u64, test_success, test_failure);

    // let dev = get_device_key_chain();
    // let user = get_user_key_chain();
    // user_refresh(rt, dev, user, 0, test_webview, test_webview_success, test_webview_failure);

    let p: *const Package = t.blocking_recv().unwrap();
    let dev = get_device_key_chain();
    let user = get_user_key_chain();

    let (r, mut t) = tokio::sync::mpsc::channel(1);
    let r = Arc::new(r);
    download_all(rt, p, dev, user, c"http://assets2.xboxlive.com/14/aa14a80d-58ae-492a-8a48-b9e5ae421187/1d4dfd7a-d46b-4eaa-b2d2-d855c95bbbd1/1.75.0.0.119fa092-373a-4e87-a067-e3c4f7efa433/RawFury.StarTrucker_1.75.0.0_x64__9s0pnehqffj7t.msixvc".as_ptr(), c"/tmp/out".as_ptr(), Arc::into_raw(r.clone()) as u64, test_success2, test_failure2);
    
    // get_progress_all(package)

    // let result: Result<(), String> = t.blocking_recv().unwrap();
    // match result {
    //     Ok(_) => {},
    //     Err(e) => todo!("{}", e),
    // }
    loop {
        let result: Result<Result<(), String>, TryRecvError> = t.try_recv();
        match result {
            Ok(Ok(_)) => break,
            Ok(Err(e)) => todo!("{}", e),
            Err(TryRecvError::Empty) => {
                let p = get_progress_all(p);
                println!("{} / {}", p.cur, p.total);
                sleep(Duration::from_secs(1));
            },
            Err(e) => todo!("{}", e),
        }
    }
    // let g = r.1.lock().unwrap();
    // let g = r.0.wait(g).unwrap();
    // drop(g);
}