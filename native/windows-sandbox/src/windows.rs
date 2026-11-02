use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::Isolation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Com::CoCreateGuid;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
use windows_sys::Win32::System::Threading::*;

const POLICY_ENV: &str = "OPENCODE_WINDOWS_SANDBOX_POLICY";
const SHELL_ENV: &str = "OPENCODE_REAL_SHELL";
const READ_ACCESS: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
// Delete is an object right. Never grant FILE_DELETE_CHILD on its parent:
// that would bypass a protected child's own delete denial.
const WRITE_ACCESS: u32 = FILE_GENERIC_WRITE | DELETE;
const ADMIN_ACCESS: u32 = FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;
const MUTATE_ACCESS: u32 =
    (FILE_GENERIC_WRITE & !(READ_CONTROL | SYNCHRONIZE)) | DELETE | ADMIN_ACCESS;
const MAX_OBJECTS: usize = 100_000;
// The real Windows matrix passed for PowerShell 7 and cmd, including ACL
// restoration and cancellation. Keep a compile-time stop available for future
// contract failures; this is deliberately not a user/environment bypass.
const ACCEPTANCE_VERIFIED: bool = true;
const ACCEPTANCE_FAILURE: &str =
    "Windows LPAC backend is disabled: the real Windows acceptance matrix is incomplete";

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    version: u32,
    profile: String,
    cwd: String,
    scratch: String,
    read_roots: Vec<String>,
    write_roots: Vec<String>,
    deny_read: Vec<String>,
    deny_write: Vec<String>,
    network: bool,
    #[serde(skip)]
    control_root: Option<PathBuf>,
}

struct Handle(HANDLE);

impl Handle {
    fn new(value: HANDLE, operation: &str) -> Result<Self> {
        if value.is_null() || value == INVALID_HANDLE_VALUE {
            Err(last_error(operation))
        } else {
            Ok(Self(value))
        }
    }
}

fn terminate_job(job: HANDLE) -> Result<()> {
    check(
        unsafe { TerminateJobObject(job, 125) },
        "TerminateJobObject",
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        check(
            unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of_val(&accounting) as u32,
                    null_mut(),
                )
            },
            "QueryInformationJobObject",
        )?;
        if accounting.ActiveProcesses == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("Sandbox Job did not terminate within the cleanup deadline".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct TerminateOnDrop(HANDLE);

impl Drop for TerminateOnDrop {
    fn drop(&mut self) {
        if let Err(error) = terminate_job(self.0) {
            // Keep the durable journal and ACLs for recovery rather than
            // announcing cleanup while a payload might still be alive.
            eprintln!("opencode-windows-sandbox: {error}");
            std::process::exit(125);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct Sid(PSID);

impl Drop for Sid {
    fn drop(&mut self) {
        unsafe { FreeSid(self.0) };
    }
}

struct Profile {
    name: Vec<u16>,
}

impl Profile {
    fn create(name: &str) -> Result<Self> {
        let name = wide(name);
        let mut sid = null_mut();
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if result < 0 {
            return Err(format!("CreateAppContainerProfile failed ({result:#x})"));
        }
        drop(Sid(sid));
        Ok(Self { name })
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.name.is_empty() {
            return Ok(());
        }
        let result = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        if result < 0 {
            return Err(format!("DeleteAppContainerProfile failed ({result:#x})"));
        }
        self.name.clear();
        Ok(())
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("opencode-windows-sandbox: {error}");
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn last_error(operation: &str) -> String {
    format!("{operation} failed (Win32 {})", unsafe { GetLastError() })
}

fn check(value: i32, operation: &str) -> Result<()> {
    if value == 0 {
        Err(last_error(operation))
    } else {
        Ok(())
    }
}

fn status(value: u32, operation: &str) -> Result<()> {
    if value != ERROR_SUCCESS {
        Err(format!("{operation} failed (Win32 {value})"))
    } else {
        Ok(())
    }
}

fn unique_name() -> Result<String> {
    let mut guid = unsafe { zeroed() };
    if unsafe { CoCreateGuid(&mut guid) } < 0 {
        return Err("Cannot allocate a unique sandbox identity".into());
    }
    Ok(format!(
        "opencode-{:08x}{:04x}{:04x}{}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

fn container_sid(name: &str) -> Result<Sid> {
    let mut sid = null_mut();
    let result =
        unsafe { DeriveAppContainerSidFromAppContainerName(wide(name).as_ptr(), &mut sid) };
    if result < 0 {
        return Err(format!("DeriveAppContainerSid failed ({result:#x})"));
    }
    Ok(Sid(sid))
}

fn denial_sid(package: PSID) -> Result<LocalAllocation> {
    // A package SID participates in LPAC's allow-only check; its DENY ACEs
    // do not veto an inherited package grant. Use a distinct per-call SID in
    // the ordinary restricting-SID check for actual denials instead.
    let package = sid_string(package)?;
    let suffix = package
        .strip_prefix("S-1-15-2-")
        .ok_or("Unexpected AppContainer SID format")?;
    let mut sid = null_mut();
    check(
        unsafe { ConvertStringSidToSidW(wide(format!("S-1-9-{suffix}")).as_ptr(), &mut sid) },
        "ConvertStringSidToSid(denial)",
    )?;
    Ok(LocalAllocation(sid))
}

fn restricted_token(denial: PSID) -> Result<Handle> {
    let mut parent = null_mut();
    check(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &mut parent,
            )
        },
        "OpenProcessToken(restriction)",
    )?;
    let parent = Handle::new(parent, "OpenProcessToken(restriction)")?;
    if unsafe { IsTokenRestricted(parent.0) } != 0 {
        return Err("An already restricted supervisor token is unsupported".into());
    }
    let mut size = 0;
    unsafe { GetTokenInformation(parent.0, TokenGroups, null_mut(), 0, &mut size) };
    let mut storage = vec![0_usize; (size as usize).div_ceil(size_of::<usize>())];
    check(
        unsafe {
            GetTokenInformation(
                parent.0,
                TokenGroups,
                storage.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        },
        "GetTokenInformation(restriction groups)",
    )?;
    let groups = unsafe { &*storage.as_ptr().cast::<TOKEN_GROUPS>() };
    let mut restricting = vec![SID_AND_ATTRIBUTES {
        Sid: denial,
        Attributes: 0,
    }];
    for index in 0..groups.GroupCount as usize {
        let group = unsafe { &*groups.Groups.as_ptr().add(index) };
        if group.Attributes & SE_GROUP_ENABLED as u32 != 0 {
            restricting.push(SID_AND_ATTRIBUTES {
                Sid: group.Sid,
                Attributes: 0,
            });
        }
    }
    // Do not put TokenUser in this list: implicit owner WRITE_DAC must not
    // bypass policy. System/logon groups retain their existing baseline;
    // LPAC still independently requires its package/capability allowance.
    // Package SIDs cannot be supplied to CreateRestrictedToken itself.
    let mut restricted = null_mut();
    check(
        unsafe {
            CreateRestrictedToken(
                parent.0,
                DISABLE_MAX_PRIVILEGE,
                0,
                null(),
                0,
                null(),
                restricting.len() as u32,
                restricting.as_ptr(),
                &mut restricted,
            )
        },
        "CreateRestrictedToken",
    )?;
    Handle::new(restricted, "CreateRestrictedToken")
}

fn sid_string(sid: PSID) -> Result<String> {
    let mut value = null_mut();
    check(
        unsafe { ConvertSidToStringSidW(sid, &mut value) },
        "ConvertSidToStringSid",
    )?;
    let allocation = LocalAllocation(value.cast());
    let mut length = 0;
    unsafe {
        while *value.add(length) != 0 {
            length += 1;
        }
    }
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) });
    drop(allocation);
    Ok(result)
}

fn process_token(process: HANDLE) -> Result<Handle> {
    let mut token = null_mut();
    check(
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) },
        "OpenProcessToken",
    )?;
    Handle::new(token, "OpenProcessToken")
}

fn token_flag(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<bool> {
    let mut flag = 0_u32;
    let mut size = 0;
    check(
        unsafe { GetTokenInformation(token, class, (&mut flag as *mut u32).cast(), 4, &mut size) },
        "GetTokenInformation",
    )?;
    Ok(flag != 0)
}

fn verify_container(token: HANDLE, expected_sid: PSID, expected_denial: PSID) -> Result<()> {
    if !token_flag(token, TokenIsAppContainer)? {
        return Err("Created process is not an AppContainer".into());
    }
    let mut size = 0;
    unsafe { GetTokenInformation(token, TokenAppContainerSid, null_mut(), 0, &mut size) };
    let mut storage = vec![0_usize; (size as usize).div_ceil(size_of::<usize>())];
    check(
        unsafe {
            GetTokenInformation(
                token,
                TokenAppContainerSid,
                storage.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        },
        "GetTokenInformation(AppContainer SID)",
    )?;
    let information = unsafe { &*storage.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>() };
    if unsafe { EqualSid(information.TokenAppContainer, expected_sid) } == 0 {
        return Err("Created process has the wrong AppContainer identity".into());
    }
    // LPAC is defined by opting out of ALL APPLICATION PACKAGES. Inspect the
    // actual enabled groups instead of relying on a newer token-information
    // class that older supported Windows versions do not implement.
    unsafe { GetTokenInformation(token, TokenGroups, null_mut(), 0, &mut size) };
    storage.resize((size as usize).div_ceil(size_of::<usize>()), 0);
    check(
        unsafe {
            GetTokenInformation(
                token,
                TokenGroups,
                storage.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        },
        "GetTokenInformation(groups)",
    )?;
    let groups = unsafe { &*storage.as_ptr().cast::<TOKEN_GROUPS>() };
    for index in 0..groups.GroupCount as usize {
        let group = unsafe { &*groups.Groups.as_ptr().add(index) };
        if group.Attributes & SE_GROUP_ENABLED as u32 != 0 && sid_string(group.Sid)? == "S-1-15-2-1"
        {
            return Err("Created process retains ALL APPLICATION PACKAGES access".into());
        }
    }
    unsafe { GetTokenInformation(token, TokenRestrictedSids, null_mut(), 0, &mut size) };
    storage.resize((size as usize).div_ceil(size_of::<usize>()), 0);
    check(
        unsafe {
            GetTokenInformation(
                token,
                TokenRestrictedSids,
                storage.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        },
        "GetTokenInformation(restricting SIDs)",
    )?;
    let groups = unsafe { &*storage.as_ptr().cast::<TOKEN_GROUPS>() };
    let found = (0..groups.GroupCount as usize).any(|index| {
        let group = unsafe { &*groups.Groups.as_ptr().add(index) };
        unsafe { EqualSid(group.Sid, expected_denial) != 0 }
    });
    if !found {
        return Err("Created process lost its per-call restricting SID".into());
    }
    Ok(())
}

fn current_user() -> Result<String> {
    let token = process_token(unsafe { GetCurrentProcess() })?;
    if token_flag(token.0, TokenIsAppContainer)? {
        return Err("A sandboxed process cannot act as the sandbox supervisor".into());
    }
    let mut size = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size) };
    let mut storage = vec![0_usize; (size as usize).div_ceil(size_of::<usize>())];
    check(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        },
        "GetTokenInformation(user)",
    )?;
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if unsafe { IsWellKnownSid(user.User.Sid, WinLocalSystemSid) } != 0 {
        return Err(
            "SYSTEM is not a supported payload identity; launch as the interactive user".into(),
        );
    }
    sid_string(user.User.Sid)
}

fn validate_path(value: &str) -> Result<PathBuf> {
    let bytes = value.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
        || value[2..].contains(':')
        || value
            .chars()
            .any(|character| character < ' ' || "<>\"|?*".contains(character))
    {
        return Err(
            "Only absolute, local drive paths are supported (no UNC, devices or ADS)".into(),
        );
    }
    for component in value[3..]
        .split(['\\', '/'])
        .filter(|part| !part.is_empty())
    {
        let reserved = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if component == "."
            || component == ".."
            || component.ends_with(['.', ' '])
            || matches!(reserved.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (reserved.len() == 4
                && (reserved.starts_with("COM") || reserved.starts_with("LPT"))
                && reserved.as_bytes()[3].is_ascii_digit())
        {
            return Err("Ambiguous or reserved Windows path component".into());
        }
    }
    Ok(PathBuf::from(value.replace('/', "\\")))
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().trim_end_matches('\\').to_lowercase()
}

fn canonical_path(value: &str) -> Result<PathBuf> {
    let path = validate_path(value)?;
    let _ancestors = lock_ancestors(&path)?;
    let file = open_checked(&path, false, true)?;
    let mut buffer = vec![0_u16; 32768];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if count == 0 || count as usize >= buffer.len() {
        return Err(last_error("GetFinalPathNameByHandle"));
    }
    let name = String::from_utf16_lossy(&buffer[..count as usize]);
    let name = name
        .strip_prefix("\\\\?\\")
        .ok_or("Policy target is not on a local DOS volume")?;
    validate_path(name)
}

fn beneath(path: &Path, root: &Path) -> bool {
    let path = path_key(path);
    let root = path_key(root);
    path == root || path.starts_with(&(root + "\\"))
}

fn matches_path(path: &Path, roots: &[String]) -> bool {
    roots.iter().any(|root| beneath(path, Path::new(root)))
}

fn open_checked(path: &Path, writable_acl: bool, pin_object: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    // Never keep data-write access to an executable: Windows cannot create
    // an image section while a file has an incompatible writer open.
    options.access_mode(
        FILE_READ_ATTRIBUTES | READ_CONTROL | if writable_acl { WRITE_DAC } else { 0 },
    );
    // Boundary roots and protected ancestors stay pinned. Ordinary objects
    // retain identity through their handles while supporting atomic saves.
    let mut sharing = FILE_SHARE_READ | FILE_SHARE_WRITE;
    if !pin_object {
        sharing |= FILE_SHARE_DELETE;
    }
    // Pin the name during validation and any reopen below. A grant handle
    // may allow rename only after it refers to that same checked object.
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    let file = options
        .open(path)
        .map_err(|error| format!("Cannot securely open a policy path: {error}"))?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    check(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) },
        "GetFileInformationByHandle",
    )?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("Reparse points are not supported in grant trees".into());
    }
    if !pin_object {
        return OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL | if writable_acl { WRITE_DAC } else { 0 })
            .share_mode(sharing)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .map_err(|error| format!("Cannot reopen checked grant object: {error}"));
    }
    Ok(file)
}

fn lock_ancestors(path: &Path) -> Result<Vec<File>> {
    let mut current = PathBuf::new();
    let mut locks = Vec::new();
    for component in path.components() {
        current.push(component);
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        if current == path {
            break;
        }
        locks.push(open_checked(&current, false, true)?);
    }
    Ok(locks)
}

fn file_acl(file: &File) -> Result<(LocalAllocation, *mut ACL)> {
    let mut descriptor = null_mut();
    let mut acl = null_mut();
    status(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        },
        "GetSecurityInfo",
    )?;
    if acl.is_null() {
        unsafe { LocalFree(descriptor) };
        return Err("Objects with a NULL DACL cannot be granted to a sandbox".into());
    }
    Ok((LocalAllocation(descriptor), acl))
}

fn edit_acl(
    file: &File,
    sid: PSID,
    mode: ACCESS_MODE,
    access: u32,
    inheritance: u32,
) -> Result<()> {
    let mutex = Handle::new(
        unsafe {
            CreateMutexW(
                null(),
                0,
                wide("Local\\OpenCodeWindowsSandboxAcl-v1").as_ptr(),
            )
        },
        "CreateMutex(ACL)",
    )?;
    match unsafe { WaitForSingleObject(mutex.0, 30_000) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => {}
        _ => return Err("Cannot acquire the sandbox ACL update lock".into()),
    }
    struct Unlock(HANDLE);
    impl Drop for Unlock {
        fn drop(&mut self) {
            unsafe { ReleaseMutex(self.0) };
        }
    }
    let _unlock = Unlock(mutex.0);
    let (original_descriptor, old_acl) = file_acl(file)?;
    if mode == REVOKE_ACCESS {
        let mut present = false;
        for index in 0..unsafe { (*old_acl).AceCount } as u32 {
            let mut ace = null_mut();
            check(unsafe { GetAce(old_acl, index, &mut ace) }, "GetAce")?;
            let entry = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            if matches!(entry.Header.AceType, 0 | 1)
                && unsafe { EqualSid((&entry.SidStart as *const u32).cast_mut().cast(), sid) } != 0
            {
                present = true;
                break;
            }
        }
        if !present {
            return Ok(());
        }
    }
    let mut entry: EXPLICIT_ACCESS_W = unsafe { zeroed() };
    entry.grfAccessPermissions = access;
    entry.grfAccessMode = mode;
    entry.grfInheritance = inheritance;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    entry.Trustee.ptstrName = sid.cast();
    let mut new_acl = null_mut();
    status(
        unsafe { SetEntriesInAclW(1, &entry, old_acl, &mut new_acl) },
        "SetEntriesInAcl",
    )?;
    let _new_acl = LocalAllocation(new_acl.cast());
    if mode == REVOKE_ACCESS {
        // SetEntriesInAcl's revoke mode can retain DENY and inherited ACEs.
        // Delete every ACE we own explicitly, without touching another SID.
        for index in (0..unsafe { (*new_acl).AceCount } as u32).rev() {
            let mut ace = null_mut();
            check(unsafe { GetAce(new_acl, index, &mut ace) }, "GetAce(revoke)")?;
            let entry = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            if matches!(entry.Header.AceType, 0 | 1)
                && unsafe { EqualSid((&entry.SidStart as *const u32).cast_mut().cast(), sid) } != 0
            {
                check(unsafe { DeleteAce(new_acl, index) }, "DeleteAce(revoke)")?;
            }
        }
    }
    let mut control = 0;
    let mut revision = 0;
    check(
        unsafe { GetSecurityDescriptorControl(original_descriptor.0, &mut control, &mut revision) },
        "GetSecurityDescriptorControl",
    )?;
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { zeroed() };
    let descriptor_pointer = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    check(
        unsafe { InitializeSecurityDescriptor(descriptor_pointer, 1) },
        "InitializeSecurityDescriptor",
    )?;
    check(
        unsafe {
            SetSecurityDescriptorDacl(
                descriptor_pointer,
                1,
                new_acl,
                if control & SE_DACL_DEFAULTED != 0 { 1 } else { 0 },
            )
        },
        "SetSecurityDescriptorDacl",
    )?;
    let inheritance_control = SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ;
    check(
        unsafe {
            SetSecurityDescriptorControl(
                descriptor_pointer,
                inheritance_control,
                control & inheritance_control,
            )
        },
        "SetSecurityDescriptorControl",
    )?;
    // Set exactly this checked object's DACL. Unlike SetSecurityInfo, the
    // native operation does not walk unchecked descendants. ACL-only handles
    // also avoid MAXIMUM_ALLOWED's delete-sharing and executable-write locks.
    let result = unsafe {
        NtSetSecurityObject(file.as_raw_handle(), DACL_SECURITY_INFORMATION, descriptor_pointer)
    };
    if result < 0 {
        return Err(format!("NtSetSecurityObject(DACL) failed ({result:#x})"));
    }
    Ok(())
}

struct Grants {
    sid: Sid,
    denial: LocalAllocation,
    // Keeping handles makes rollback target the same object, never a replaced
    // path. REVOKE_ACCESS removes only this call's SID, not another user's edits.
    files: Vec<File>,
    ancestors: Vec<File>,
    setup_locks: Vec<File>,
    roots: Vec<PathBuf>,
    cancelled: Arc<AtomicBool>,
    scratch: PathBuf,
}

impl Grants {
    fn new(sid: Sid, cancelled: Arc<AtomicBool>) -> Result<Self> {
        Ok(Self {
            denial: denial_sid(sid.0)?,
            sid,
            files: Vec::new(),
            ancestors: Vec::new(),
            setup_locks: Vec::new(),
            roots: Vec::new(),
            cancelled,
            scratch: PathBuf::new(),
        })
    }

    fn add_tree(&mut self, path: &Path, policy: &Policy, scratch: bool) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("Sandbox preparation cancelled".into());
        }
        if policy.control_root.as_ref().is_some_and(|root| beneath(path, root)) {
            return Ok(());
        }
        if !scratch && path_key(path) == path_key(&self.scratch) {
            return Ok(());
        }
        if self.files.len() >= MAX_OBJECTS {
            return Err("Sandbox grant tree exceeds 100000 objects".into());
        }
        let pin_object = self.roots.iter().any(|root| path_key(root) == path_key(path))
            || policy
                .deny_read
                .iter()
                .chain(&policy.deny_write)
                .any(|protected| beneath(Path::new(protected), path));
        let file = open_checked(path, true, true)?;
        let directory = file.metadata().map_err(|error| error.to_string())?.is_dir();
        let file = if pin_object {
            file
        } else {
            let grant = open_checked(path, true, false)?;
            if directory {
                // Prevent a concurrent rename/junction swap while the setup
                // walk still resolves descendants by path. Release these
                // temporary pins only once all ACL grants are complete.
                self.setup_locks.push(file);
            }
            grant
        };
        let denied_read = matches_path(path, &policy.deny_read);
        let denied_write = policy.profile == "ro" || matches_path(path, &policy.deny_write);
        let writable = scratch || (!denied_write && matches_path(path, &policy.write_roots));
        if writable && !directory {
            let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
            check(
                unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) },
                "GetFileInformationByHandle(write grant)",
            )?;
            // Read-only runtime aliases expose no new data: the same bytes
            // are already readable through the granted installation path.
            // A write grant must not mutate an ungranted external hardlink.
            if information.nNumberOfLinks > 1 {
                return Err("A writable grant cannot include a multiply-linked file".into());
            }
        }
        let readable = scratch
            || matches_path(path, &policy.read_roots)
            || matches_path(path, &policy.write_roots);
        let inheritance = if directory {
            CONTAINER_INHERIT_ACE as u32 | OBJECT_INHERIT_ACE as u32
        } else {
            0
        };
        self.files.push(file);
        let file = self.files.last().unwrap();
        if denied_read {
            edit_acl(file, self.denial.0, DENY_ACCESS, FILE_ALL_ACCESS, inheritance)?;
        } else {
            edit_acl(
                file,
                self.denial.0,
                DENY_ACCESS,
                if writable {
                    ADMIN_ACCESS
                } else {
                    MUTATE_ACCESS
                },
                inheritance,
            )?;
            if readable {
                edit_acl(
                    file,
                    self.denial.0,
                    GRANT_ACCESS,
                    READ_ACCESS | if writable { WRITE_ACCESS } else { 0 },
                    inheritance,
                )?;
                edit_acl(
                    file,
                    self.sid.0,
                    GRANT_ACCESS,
                    READ_ACCESS | if writable { WRITE_ACCESS } else { 0 },
                    inheritance,
                )?;
            }
        }
        if directory {
            for entry in fs::read_dir(path)
                .map_err(|error| format!("Cannot inspect grant directory: {error}"))?
            {
                let entry = entry.map_err(|error| error.to_string())?;
                self.add_tree(&entry.path(), policy, scratch)?;
            }
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut failure = None;
        // DACL updates target these checked handles without automatic traversal.
        for file in &self.files {
            if let Err(error) = edit_acl(file, self.sid.0, REVOKE_ACCESS, 0, 0) {
                failure.get_or_insert(error);
            }
            if let Err(error) = edit_acl(file, self.denial.0, REVOKE_ACCESS, 0, 0) {
                failure.get_or_insert(error);
            }
        }
        // Newly created descendants inherited this SID but were not present
        // during setup. With the Job dead, revoke them via a second no-follow
        // walk. Existing user ACEs and unrelated concurrent-call SIDs remain.
        for root in &self.roots {
            if let Err(error) = revoke_tree(root, self.sid.0) {
                failure.get_or_insert(error);
            }
            if let Err(error) = revoke_tree(root, self.denial.0) {
                failure.get_or_insert(error);
            }
        }
        self.files.clear();
        self.setup_locks.clear();
        self.roots.clear();
        self.ancestors.clear();
        match failure {
            Some(error) => Err(format!(
                "A sandbox-specific ACL could not be removed: {error}"
            )),
            None => Ok(()),
        }
    }
}

fn revoke_tree(path: &Path, sid: PSID) -> Result<()> {
    // Cleanup removes authority, never adds it. Open the reparse object itself
    // and never follow it, including links created by the payload after setup.
    let file = match OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("Cannot open sandbox ACL cleanup target: {error}")),
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    check(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) },
        "GetFileInformationByHandle(cleanup)",
    )?;
    let directory = file.metadata().map_err(|error| error.to_string())?.is_dir();
    edit_acl(&file, sid, REVOKE_ACCESS, 0, 0)?;
    if directory && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        let mut failed = false;
        for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
            if revoke_tree(&entry.map_err(|error| error.to_string())?.path(), sid).is_err() {
                failed = true;
            }
        }
        if failed {
            return Err("One or more descendant ACLs could not be revoked".into());
        }
    }
    Ok(())
}

impl Drop for Grants {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("opencode-windows-sandbox: {error}");
        }
    }
}

fn private_directory(path: &Path, user: &str) -> Result<()> {
    let sddl = wide(format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})"));
    let mut descriptor = null_mut();
    check(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        },
        "ConvertStringSecurityDescriptor",
    )?;
    let _descriptor = LocalAllocation(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    check(
        unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) },
        "CreateDirectory(private scratch)",
    )
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    identity: String,
    pid: u32,
    roots: Vec<PathBuf>,
    scratch: PathBuf,
}

struct Control {
    file: File,
    token: String,
    stopped: Arc<AtomicBool>,
}

impl Control {
    fn connect(cancelled: Arc<AtomicBool>) -> Result<Option<Self>> {
        let pipe = env::var("OPENCODE_WINDOWS_CONTROL_PIPE").ok();
        let token = env::var("OPENCODE_WINDOWS_CONTROL_TOKEN").ok();
        let (pipe, token) = match (pipe, token) {
            (None, None) => return Ok(None),
            (Some(pipe), Some(token)) => (pipe, token),
            _ => return Err("The sandbox control pipe and token must be supplied together".into()),
        };
        if !pipe.starts_with("\\\\.\\pipe\\opencode-security-")
            || pipe.contains(['\r', '\n', '\0'])
            || token.len() < 32
            || token.len() > 256
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("Invalid sandbox control channel".into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe)
            .map_err(|_| "Cannot connect to the sandbox cancellation channel")?;
        let ready = serde_json::json!({ "version": 1, "type": "ready", "token": token });
        writeln!(file, "{ready}")
            .map_err(|_| "Cannot authenticate the sandbox cancellation channel")?;
        file.flush()
            .map_err(|_| "Cannot flush sandbox ready frame")?;
        let mut reader = file
            .try_clone()
            .map_err(|_| "Cannot monitor sandbox cancellation channel")?;
        let stopped = Arc::new(AtomicBool::new(false));
        let reader_stopped = stopped.clone();
        thread::spawn(move || {
            // There are no permitted host-to-helper messages except cancel.
            // Fail closed immediately on a partial frame, garbage, EOF or I/O
            // error; never wait for a newline while the payload keeps running.
            // A blocking read on a duplicated synchronous pipe handle can
            // serialize an exit-frame write on that same file object forever.
            // Peek instead; any input byte or disconnection is cancellation.
            while !reader_stopped.load(Ordering::Acquire) {
                let mut available = 0;
                let connected = unsafe {
                    PeekNamedPipe(
                        reader.as_raw_handle(),
                        null_mut(),
                        0,
                        null_mut(),
                        &mut available,
                        null_mut(),
                    )
                };
                if connected == 0 {
                    cancelled.store(true, Ordering::Release);
                    return;
                }
                if available > 0 {
                    // Consume the queued signal so a sender flushing its
                    // pipe is not left waiting while we send the exit frame.
                    let mut input = [0_u8; 256];
                    let length = (available as usize).min(input.len());
                    let _ = reader.read(&mut input[..length]);
                    cancelled.store(true, Ordering::Release);
                    return;
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        Ok(Some(Self { file, token, stopped }))
    }

    fn finished(&mut self, code: i32) -> Result<()> {
        self.stopped.store(true, Ordering::Release);
        let frame =
            serde_json::json!({ "version": 1, "type": "exit", "token": self.token, "exit": code });
        writeln!(self.file, "{frame}").map_err(|_| "Cannot deliver sandbox exit frame")?;
        self.file
            .flush()
            .map_err(|_| "Cannot flush sandbox exit frame".to_string())
    }
}

fn state_directory(user: &str) -> Result<PathBuf> {
    let base = validate_path(&env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA is missing")?)?;
    let _locks = lock_ancestors(&base.join("opencode-windows-sandbox-state"))?;
    let state = base.join("opencode-windows-sandbox-state");
    if !state.exists() {
        private_directory(&state, user)?;
    }
    let _state = open_checked(&state, false, true)?;
    Ok(state)
}

fn recover(state: &Path) -> Result<()> {
    for entry in fs::read_dir(state).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let journal: Journal = {
            let _checked = open_checked(&path, false, true)?;
            let reader = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
                .map_err(|_| "Cannot read sandbox recovery journal")?;
            serde_json::from_reader(reader).map_err(|_| "Invalid sandbox recovery journal")?
        };
        if journal.identity.len() != 41
            || !journal.identity.starts_with("opencode-")
            || !journal.identity[9..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || journal
                .scratch
                .file_name()
                .is_none_or(|name| name != journal.identity.as_str())
        {
            return Err("Invalid sandbox recovery identity".into());
        }
        let process = unsafe { OpenProcess(SYNCHRONIZE, 0, journal.pid) };
        if !process.is_null() {
            let process = Handle::new(process, "OpenProcess(recovery)")?;
            if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_OBJECT_0 {
                continue;
            }
        } else if unsafe { GetLastError() } != ERROR_INVALID_PARAMETER {
            return Err("Cannot determine whether an earlier sandbox is still running".into());
        }
        let sid = container_sid(&journal.identity)?;
        let denial = denial_sid(sid.0)?;
        for root in &journal.roots {
            validate_path(&root.to_string_lossy())?;
            if !root.exists() {
                continue;
            }
            let _ancestors = lock_ancestors(root)?;
            revoke_tree(root, sid.0)?;
            revoke_tree(root, denial.0)?;
        }
        if journal.scratch.exists() {
            let checked = open_checked(&journal.scratch, false, true)?;
            drop(checked);
            fs::remove_dir_all(&journal.scratch)
                .map_err(|_| "Cannot remove recovered sandbox scratch")?;
        }
        let result = unsafe { DeleteAppContainerProfile(wide(&journal.identity).as_ptr()) };
        // ERROR_FILE_NOT_FOUND is harmless if setup failed before registration.
        if result < 0 && result as u32 != 0x80070002 {
            return Err(format!(
                "Cannot remove recovered AppContainer profile ({result:#x})"
            ));
        }
        fs::remove_file(path).map_err(|_| "Cannot remove recovered sandbox journal")?;
    }
    Ok(())
}

fn runtime_root(shell: &Path, windows: &Path) -> Result<Option<PathBuf>> {
    if beneath(shell, windows) {
        return Ok(None);
    }
    let mut root = shell
        .parent()
        .ok_or("Shell has no installation directory")?
        .to_path_buf();
    let name = shell
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    // Git for Windows resolves its DLLs, /usr and /etc relative to Git's root.
    if name == "bash.exe" || name == "sh.exe" {
        if root
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("bin"))
        {
            root.pop();
            if root
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("usr"))
            {
                root.pop();
            }
        }
    }
    if root.parent().is_none() || root.components().count() < 3 {
        return Err("A volume-wide shell runtime grant is not supported".into());
    }
    Ok(Some(root))
}

fn normalized_policy(mut policy: Policy) -> Result<Policy> {
    if policy.version != 1 || !matches!(policy.profile.as_str(), "ro" | "workspace") {
        return Err("Unsupported Windows sandbox policy version/profile".into());
    }
    policy.cwd = canonical_path(&policy.cwd)?.to_string_lossy().into_owned();
    policy.scratch = canonical_path(&policy.scratch)?
        .to_string_lossy()
        .into_owned();
    for roots in [
        &mut policy.read_roots,
        &mut policy.write_roots,
        &mut policy.deny_read,
        &mut policy.deny_write,
    ] {
        for root in roots.iter_mut() {
            let path = canonical_path(root)?;
            if path.components().count() < 3 {
                return Err("Volume-wide policy roots are not supported".into());
            }
            *root = path.to_string_lossy().into_owned();
        }
    }
    if policy.profile == "ro" {
        policy.write_roots.clear();
    }
    if !matches_path(Path::new(&policy.cwd), &policy.read_roots)
        && !matches_path(Path::new(&policy.cwd), &policy.write_roots)
    {
        return Err("Working directory must be inside an explicit read/write root".into());
    }
    Ok(policy)
}

fn shell_arguments(shell: &Path, arguments: Vec<OsString>) -> Result<Vec<OsString>> {
    let name = shell
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    if name == "powershell.exe" {
        return Err("Windows PowerShell 5.1 is not supported by this LPAC runtime; select PowerShell 7 (pwsh.exe) or cmd".into());
    }
    if matches!(name.as_str(), "bash.exe" | "sh.exe" | "zsh.exe" | "dash.exe") {
        return Err("MSYS/Cygwin shells require unsupported global named-object access; select PowerShell or cmd".into());
    }
    if arguments.len() != 2 || arguments[0] != "-c" {
        return Ok(arguments);
    }
    let command = arguments[1].clone();
    match name.as_str() {
        "pwsh.exe" => {
            Ok(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
                .into_iter()
                .map(OsString::from)
                .chain([command])
                .collect())
        }
        "cmd.exe" => Ok(["/d", "/s", "/c"]
            .into_iter()
            .map(OsString::from)
            .chain([command])
            .collect()),
        _ => Err(
            "Generic -c launch is unsupported for this shell; supply explicit shell argv".into(),
        ),
    }
}

fn append_argument(command: &mut Vec<u16>, value: &OsStr) {
    if !command.is_empty() {
        command.push(b' ' as u16);
    }
    let units: Vec<u16> = value.encode_wide().collect();
    if !units.is_empty() && !units.iter().any(|unit| matches!(*unit, 9 | 32 | 34)) {
        command.extend(units);
        return;
    }
    command.push(b'"' as u16);
    let mut backslashes = 0;
    for unit in value.encode_wide() {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
        } else {
            command.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
        }
        command.push(unit);
        backslashes = 0;
    }
    command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    command.push(b'"' as u16);
}

fn command_line(shell: &Path, arguments: &[OsString]) -> Vec<u16> {
    let mut command = Vec::new();
    append_argument(&mut command, shell.as_os_str());
    let cmd = shell
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("cmd.exe"));
    for (index, argument) in arguments.iter().enumerate() {
        // cmd /c is not a CRT argv parser. Preserve the command string's own
        // quotation rather than inserting backslashes before double quotes.
        if cmd && index > 0 && arguments[index - 1].eq_ignore_ascii_case("/c") {
            command.push(b' ' as u16);
            command.push(b'"' as u16);
            command.extend(argument.encode_wide());
            command.push(b'"' as u16);
        } else {
            append_argument(&mut command, argument);
        }
    }
    command.push(0);
    command
}

fn payload_environment(scratch: &Path, shell: &Path, windows: &Path) -> Vec<u16> {
    let mut values = BTreeMap::<String, OsString>::new();
    values.insert("SYSTEMROOT".into(), windows.as_os_str().to_owned());
    values.insert("WINDIR".into(), windows.as_os_str().to_owned());
    values.insert(
        "SYSTEMDRIVE".into(),
        OsString::from(&windows.to_string_lossy()[..2]),
    );
    values.insert(
        "COMSPEC".into(),
        windows.join("System32\\cmd.exe").into_os_string(),
    );
    let mut path = windows.join("System32").into_os_string();
    path.push(";");
    path.push(windows);
    if let Some(parent) = shell.parent() {
        path.push(";");
        path.push(parent);
    }
    values.insert("PATH".into(), path);
    values.insert("PATHEXT".into(), OsString::from(".COM;.EXE;.BAT;.CMD"));
    for key in [
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    ] {
        values.insert(key.into(), scratch.as_os_str().to_owned());
    }
    values.insert("DOTNET_CLI_TELEMETRY_OPTOUT".into(), "1".into());
    values.insert("POWERSHELL_TELEMETRY_OPTOUT".into(), "1".into());
    values.insert("DOTNET_EnableDiagnostics".into(), "0".into());
    let mut result = Vec::new();
    for (key, value) in values {
        result.extend(OsStr::new(&key).encode_wide());
        result.push(b'=' as u16);
        result.extend(value.encode_wide());
        result.push(0);
    }
    result.push(0);
    result
}

struct Attributes {
    storage: Vec<usize>,
}

impl Attributes {
    fn new(count: u32) -> Result<Self> {
        let mut size = 0;
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        let mut result = Self {
            storage: vec![0; size.div_ceil(size_of::<usize>())],
        };
        check(
            unsafe { InitializeProcThreadAttributeList(result.pointer(), count, 0, &mut size) },
            "InitializeProcThreadAttributeList",
        )?;
        Ok(result)
    }

    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }

    fn add<T>(&mut self, key: u32, value: &mut T) -> Result<()> {
        check(
            unsafe {
                UpdateProcThreadAttribute(
                    self.pointer(),
                    0,
                    key as usize,
                    (value as *mut T).cast(),
                    size_of::<T>(),
                    null_mut(),
                    null_mut(),
                )
            },
            "UpdateProcThreadAttribute",
        )
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}

fn pipe() -> Result<(Handle, Handle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    check(
        unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) },
        "CreatePipe",
    )?;
    let read = Handle::new(read, "CreatePipe(read)")?;
    let write = Handle::new(write, "CreatePipe(write)")?;
    check(
        unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, 0) },
        "SetHandleInformation",
    )?;
    Ok((read, write))
}

fn relay(input: Handle, stderr: bool, completed: mpsc::Sender<()>) {
    let handle = input.0 as usize;
    std::mem::forget(input);
    thread::spawn(move || {
        let mut file = unsafe { File::from_raw_handle(handle as HANDLE) };
        if stderr {
            let _ = std::io::copy(&mut file, &mut std::io::stderr());
        } else {
            let _ = std::io::copy(&mut file, &mut std::io::stdout());
        }
        let _ = completed.send(());
    });
}

fn capability(name: &str) -> Result<LocalAllocation> {
    let mut groups = null_mut();
    let mut group_count = 0;
    let mut capabilities = null_mut();
    let mut count = 0;
    check(
        unsafe {
            DeriveCapabilitySidsFromName(
                wide(name).as_ptr(),
                &mut groups,
                &mut group_count,
                &mut capabilities,
                &mut count,
            )
        },
        "DeriveCapabilitySidsFromName",
    )?;
    unsafe {
        for index in 0..group_count {
            LocalFree(*groups.add(index as usize));
        }
        LocalFree(groups.cast());
    }
    if count != 1 {
        unsafe {
            for index in 0..count {
                LocalFree(*capabilities.add(index as usize));
            }
            LocalFree(capabilities.cast());
        }
        return Err("Capability derivation did not return one SID".into());
    }
    let sid = unsafe { *capabilities };
    unsafe { LocalFree(capabilities.cast()) };
    Ok(LocalAllocation(sid))
}

fn spawn_payload(
    policy: &Policy,
    shell: &Path,
    arguments: &[OsString],
    scratch: &Path,
    sid: PSID,
    cancelled: &AtomicBool,
) -> Result<i32> {
    let denial = denial_sid(sid)?;
    let restricted = restricted_token(denial.0)?;
    let windows = validate_path(&env::var("SystemRoot").map_err(|_| "SystemRoot is missing")?)?;
    let job = Handle::new(
        unsafe { CreateJobObjectW(null(), null()) },
        "CreateJobObject",
    )?;
    let terminate_on_drop = TerminateOnDrop(job.0);
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    check(
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
            )
        },
        "SetInformationJobObject",
    )?;
    let (stdout_read, stdout_write) = pipe()?;
    let (stderr_read, stderr_write) = pipe()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let stdin = Handle::new(
        unsafe {
            CreateFileW(
                wide("NUL").as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        },
        "Open NUL",
    )?;
    let mut inherited = [stdin.0, stdout_write.0, stderr_write.0];
    // PowerShell and other managed runtimes register ETW providers at startup.
    // This capability matches their existing ETW descriptor's baseline event
    // rights; it neither changes host ETW ACLs nor grants network/file access.
    let mut capabilities = vec![
        capability("registryRead")?,
        capability("lpacInstrumentation")?,
    ];
    if policy.network {
        capabilities.push(capability("internetClient")?);
        capabilities.push(capability("privateNetworkClientServer")?);
    }
    let mut capability_entries: Vec<SID_AND_ATTRIBUTES> = capabilities
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.0,
            Attributes: SE_GROUP_ENABLED as u32,
        })
        .collect();
    let mut security = SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: capability_entries.as_mut_ptr(),
        CapabilityCount: capability_entries.len() as u32,
        Reserved: 0,
    };
    let mut lpac = 1_u32; // PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
    let mut jobs = [job.0];
    let mut list = Attributes::new(4)?;
    list.add(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &mut security)?;
    list.add(
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        &mut lpac,
    )?;
    list.add(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &mut inherited)?;
    // Atomic assignment eliminates the suspended-process orphan window.
    list.add(PROC_THREAD_ATTRIBUTE_JOB_LIST, &mut jobs)?;
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.0;
    startup.StartupInfo.hStdOutput = stdout_write.0;
    startup.StartupInfo.hStdError = stderr_write.0;
    startup.lpAttributeList = list.pointer();
    let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
    let mut command = command_line(shell, arguments);
    let mut environment = payload_environment(scratch, shell, &windows);
    if cancelled.load(Ordering::Acquire) {
        return Err("Sandbox launch cancelled".into());
    }
    check(
        unsafe {
            CreateProcessAsUserW(
                restricted.0,
                wide(shell).as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW,
                environment.as_mut_ptr().cast(),
                wide(&policy.cwd).as_ptr(),
                &startup.StartupInfo,
                &mut information,
            )
        },
        "CreateProcess(LPAC)",
    )?;
    let process = Handle::new(information.hProcess, "CreateProcess(process)")?;
    let initial_thread = Handle::new(information.hThread, "CreateProcess(thread)")?;
    // Never infer success from an accepted attribute. Verify the kernel token
    // before the first payload instruction executes.
    let token = process_token(process.0)?;
    verify_container(token.0, sid, denial.0)?;
    if cancelled.load(Ordering::Acquire) {
        return Err("Sandbox launch cancelled before resuming the payload".into());
    }
    if unsafe { ResumeThread(initial_thread.0) } == u32::MAX {
        return Err(last_error("ResumeThread"));
    }
    drop(stdout_write);
    drop(stderr_write);
    let (completed, receiver) = mpsc::channel();
    relay(stdout_read, false, completed.clone());
    relay(stderr_read, true, completed);
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err("Sandbox cancelled; its entire process tree was terminated".into());
        }
        match unsafe { WaitForSingleObject(process.0, 50) } {
            WAIT_OBJECT_0 => break,
            WAIT_TIMEOUT => {}
            _ => return Err(last_error("WaitForSingleObject")),
        }
    }
    let mut exit_code = 125;
    check(
        unsafe { GetExitCodeProcess(process.0, &mut exit_code) },
        "GetExitCodeProcess",
    )?;
    // Keep KILL_ON_JOB_CLOSE enabled on normal exit too. Detached grandchildren
    // must not outlive the call or retain the temporary filesystem authority.
    drop(terminate_on_drop);
    drop(job);
    for _ in 0..2 {
        let _ = receiver.recv_timeout(Duration::from_secs(2));
    }
    Ok(exit_code as i32)
}

fn execute_worker(arguments: Vec<OsString>, cancelled: Arc<AtomicBool>) -> Result<i32> {
    if !ACCEPTANCE_VERIFIED {
        return Err(ACCEPTANCE_FAILURE.into());
    }
    let user = current_user()?;
    let policy_text = env::var(POLICY_ENV).map_err(|_| "Windows sandbox policy is missing")?;
    if policy_text.len() > 96_000 {
        return Err("Windows sandbox policy is too large".into());
    }
    let mut policy = normalized_policy(
        serde_json::from_str(&policy_text).map_err(|_| "Invalid Windows sandbox policy JSON")?,
    )?;
    let shell =
        canonical_path(&env::var(SHELL_ENV).map_err(|_| "OPENCODE_REAL_SHELL is missing")?)?;
    let arguments = shell_arguments(&shell, arguments)?;
    let windows = validate_path(&env::var("SystemRoot").map_err(|_| "SystemRoot is missing")?)?;
    if policy
        .write_roots
        .iter()
        .any(|root| beneath(Path::new(root), &windows))
    {
        return Err(
            "Persistent write grants inside the Windows installation are unsupported".into(),
        );
    }
    // OS binaries and DLLs already have Windows-owned LPAC ACLs. Never mutate
    // System32/WinSxS ACLs or expand their platform-defined readable surface.
    policy
        .read_roots
        .retain(|root| !beneath(Path::new(root), &windows));
    if let Some(runtime) = runtime_root(&shell, &windows)? {
        // Runtime is executable/readable only, never implicitly writable.
        policy
            .read_roots
            .push(runtime.to_string_lossy().into_owned());
    }
    let name = unique_name()?;
    let state = state_directory(&user)?;
    recover(&state)?;
    if policy.write_roots.iter().any(|root| {
        beneath(&state, Path::new(root)) || beneath(Path::new(root), &state)
    }) || policy.read_roots.iter().any(|root| beneath(Path::new(root), &state)) {
        return Err("Grant roots must not overlap the sandbox control-state directory".into());
    }
    policy.control_root = Some(state.clone());
    let mut grants = Grants::new(container_sid(&name)?, cancelled.clone())?;
    let scratch_base = PathBuf::from(&policy.scratch);
    grants.ancestors.extend(lock_ancestors(&scratch_base)?);
    let scratch = scratch_base.join(&name);
    grants.scratch = scratch.clone();
    private_directory(&scratch, &user)?;
    let journal_path = state.join(format!("{name}.json"));
    let mut profile = None;
    let execution = (|| {
        let mut roots: Vec<PathBuf> = policy
            .read_roots
            .iter()
            .chain(&policy.write_roots)
            .chain(&policy.deny_read)
            .chain(&policy.deny_write)
            .map(PathBuf::from)
            .collect();
        roots.sort_by_key(|root| path_key(root));
        roots.dedup_by(|left, right| path_key(left) == path_key(right));
        // Private control data is already inaccessible to the payload. It is
        // not a grant tree even when the caller explicitly lists it as denied.
        roots.retain(|root| !beneath(root, &state));
        let all_roots = roots.clone();
        roots.retain(|root| {
            !all_roots
                .iter()
                .any(|other| other != root && beneath(root, other))
        });
        let journal = Journal {
            identity: name.clone(),
            pid: std::process::id(),
            roots: roots.iter().cloned().chain([scratch.clone()]).collect(),
            scratch: scratch.clone(),
        };
        let pending_path = journal_path.with_extension("pending");
        let mut journal_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending_path)
            .map_err(|_| "Cannot create sandbox recovery journal")?;
        serde_json::to_writer(&mut journal_file, &journal)
            .map_err(|_| "Cannot write sandbox recovery journal")?;
        journal_file
            .sync_all()
            .map_err(|_| "Cannot commit sandbox recovery journal")?;
        drop(journal_file);
        fs::rename(&pending_path, &journal_path)
            .map_err(|_| "Cannot publish sandbox recovery journal")?;
        profile = Some(Profile::create(&name)?);
        grants.ancestors.extend(lock_ancestors(&scratch)?);
        // Windows rewrites an AppContainer's TEMP beneath LOCALAPPDATA even
        // when the caller supplies TEMP explicitly. Keep that generated path
        // inside this call's private scratch and create it before ACL grants.
        fs::create_dir_all(scratch.join("Packages").join(&name).join("AC").join("Temp"))
            .map_err(|error| format!("Cannot prepare private AppContainer TEMP: {error}"))?;
        for root in &roots {
            grants.ancestors.extend(lock_ancestors(root)?);
            grants.roots.push(root.clone());
            grants.add_tree(root, &policy, false)?;
        }
        grants.roots.push(scratch.clone());
        grants.add_tree(&scratch, &policy, true)?;
        grants.setup_locks.clear();
        spawn_payload(
            &policy,
            &shell,
            &arguments,
            &scratch,
            grants.sid.0,
            &cancelled,
        )
    })();
    let cleanup = grants.cleanup();
    let scratch_cleanup = fs::remove_dir_all(&scratch)
        .map_err(|_| "Cannot remove private sandbox scratch".to_string());
    if let Err(error) = cleanup {
        if let Err(execution_error) = &execution {
            return Err(format!("{execution_error}; {error}"));
        }
        return Err(error);
    }
    scratch_cleanup?;
    if let Some(profile) = &mut profile {
        profile.cleanup()?;
    }
    if journal_path.exists() {
        fs::remove_file(journal_path).map_err(|_| "Cannot remove completed sandbox journal")?;
    }
    execution
}

fn worker(arguments: Vec<OsString>) -> Result<i32> {
    // Authenticate before parsing policy or touching ACLs. Even preparation
    // failures are terminal events for background calls in the host broker.
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut control = Control::connect(cancelled.clone())?;
    let cancellation = cancelled.clone();
    thread::spawn(move || {
        let mut byte = [0_u8; 1];
        let _ = std::io::stdin().read(&mut byte);
        cancellation.store(true, Ordering::Release);
    });
    let result = execute_worker(arguments, cancelled);
    if let Some(control) = &mut control {
        control.finished(result.as_ref().copied().unwrap_or(125))?;
    }
    result
}

fn probe() -> Result<i32> {
    if !ACCEPTANCE_VERIFIED {
        println!(
            "{}",
            serde_json::json!({
                "version": 1,
                "backend": "windows-lpac",
                "available": false,
                "contractFailure": true,
                "reason": ACCEPTANCE_FAILURE,
            })
        );
        return Ok(0);
    }
    // Probe the actual LPAC process-creation path without mutating user trees.
    let result = (|| {
        let user = current_user()?;
        recover(&state_directory(&user)?)?;
        let windows = validate_path(&env::var("SystemRoot").map_err(|_| "SystemRoot is missing")?)?;
        let name = unique_name()?;
        let mut profile = Profile::create(&name)?;
        let sid = container_sid(&name)?;
        let policy = Policy {
            version: 1,
            profile: "ro".into(),
            cwd: windows.to_string_lossy().into_owned(),
            scratch: windows.to_string_lossy().into_owned(),
            read_roots: vec![],
            write_roots: vec![],
            deny_read: vec![],
            deny_write: vec![],
            network: false,
            control_root: None,
        };
        let arguments = ["/d", "/s", "/c", "exit 0"].map(OsString::from);
        let code = spawn_payload(
            &policy,
            &windows.join("System32\\cmd.exe"),
            &arguments,
            &windows,
            sid.0,
            &AtomicBool::new(false),
        )?;
        if code != 0 {
            return Err(format!("LPAC probe payload exited {code}"));
        }
        profile.cleanup()?;
        Ok(())
    })();
    let response = match result {
        Ok(()) => serde_json::json!({ "version": 1, "backend": "windows-lpac", "available": true }),
        Err(reason) => {
            serde_json::json!({ "version": 1, "backend": "windows-lpac", "available": false, "reason": reason })
        }
    };
    println!("{response}");
    Ok(0)
}

fn run_inner() -> Result<i32> {
    let mut arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if arguments == [OsString::from("--probe")] {
        return probe();
    }
    if arguments.first().is_some_and(|value| value == "--worker") {
        arguments.remove(0);
        return worker(arguments);
    }
    // The worker owns all ACLs and the Job. It survives termination of this
    // thin launcher and observes EOF on its private cancellation pipe, so it
    // can kill the Job and revoke grants after ordinary host cancellation.
    let mut command = Command::new(env::current_exe().map_err(|error| error.to_string())?);
    command.arg("--worker").args(arguments).env_clear();
    for key in [POLICY_ENV, SHELL_ENV, "SystemRoot", "LOCALAPPDATA"] {
        command.env(
            key,
            env::var_os(key).ok_or("A required sandbox launcher environment value is missing")?,
        );
    }
    for key in [
        "OPENCODE_WINDOWS_CONTROL_PIPE",
        "OPENCODE_WINDOWS_CONTROL_TOKEN",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    let mut child = command
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("Cannot start sandbox cleanup supervisor: {error}"))?;
    let control = child
        .stdin
        .take()
        .ok_or("Missing sandbox cancellation pipe")?;
    let result = child.wait().map_err(|error| error.to_string());
    drop(control);
    Ok(result?.code().unwrap_or(125))
}

pub fn run() -> Result<i32> {
    let result = run_inner();
    // A launcher failure before the cleanup worker exists still closes the
    // host's background lease. Worker-reported exits return Ok(code), so this
    // does not open a second connection after a normal worker result.
    if result.is_err() && !env::args_os().any(|argument| argument == "--worker") {
        if let Ok(Some(mut control)) = Control::connect(Arc::new(AtomicBool::new(false))) {
            let _ = control.finished(125);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_host_command_is_adapted_to_the_real_shell() {
        for (shell, expected) in [
            ("pwsh.exe", "-NoLogo"),
            ("cmd.exe", "/d"),
        ] {
            let arguments =
                shell_arguments(Path::new(shell), vec!["-c".into(), "echo a b".into()]).unwrap();
            assert_eq!(arguments[0], expected);
            assert_eq!(arguments.last().unwrap(), "echo a b");
        }
        let explicit = vec![OsString::from("-EncodedCommand"), OsString::from("abc")];
        assert_eq!(
            shell_arguments(Path::new("pwsh.exe"), explicit.clone()).unwrap(),
            explicit
        );
        assert!(shell_arguments(Path::new("bash.exe"), vec!["-c".into(), "echo unsafe".into()]).is_err());
        assert!(shell_arguments(Path::new("bash.exe"), vec!["-lc".into(), "echo unsafe".into()]).is_err());
        assert!(shell_arguments(Path::new("powershell.exe"), vec!["-Command".into(), "echo unsafe".into()]).is_err());
    }

    #[test]
    fn rejects_ambiguous_paths_and_respects_component_boundaries() {
        for path in [
            "C:relative",
            "\\\\server\\share",
            "C:\\a:stream",
            "C:\\a\\..\\b",
            "C:\\NUL",
        ] {
            assert!(validate_path(path).is_err());
        }
        assert!(beneath(Path::new("C:\\WORK\\a"), Path::new("c:\\work")));
        assert!(!beneath(Path::new("C:\\workspace"), Path::new("C:\\work")));
    }
}
