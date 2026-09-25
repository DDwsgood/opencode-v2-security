#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

#[cfg(not(windows))]
compile_error!("opencode-bash-supervisor is a Windows-only prototype");

#[cfg(windows)]
mod windows {
    use std::env;
    use std::ffi::{OsStr, OsString, c_void};
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    type Bool = i32;
    type Dword = u32;
    type Handle = *mut c_void;
    type SizeT = usize;

    const FALSE: Bool = 0;
    const TRUE: Bool = 1;
    const HANDLE_FLAG_INHERIT: Dword = 0x0000_0001;
    const STARTF_USESTDHANDLES: Dword = 0x0000_0100;
    const CREATE_SUSPENDED: Dword = 0x0000_0004;
    const EXTENDED_STARTUPINFO_PRESENT: Dword = 0x0008_0000;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x0000_2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
    const STD_OUTPUT_HANDLE: Dword = (-11_i32) as Dword;
    const STD_ERROR_HANDLE: Dword = (-12_i32) as Dword;
    const GENERIC_READ: Dword = 0x8000_0000;
    const FILE_SHARE_READ: Dword = 0x0000_0001;
    const FILE_SHARE_WRITE: Dword = 0x0000_0002;
    const OPEN_EXISTING: Dword = 3;
    const FILE_ATTRIBUTE_NORMAL: Dword = 0x0000_0080;
    const INFINITE: Dword = 0xffff_ffff;
    const WAIT_OBJECT_0: Dword = 0;
    const INVALID_HANDLE_VALUE: Handle = (-1_isize) as Handle;
    const STILL_ACTIVE: Dword = 259;
    const DRAIN_GRACE: Duration = Duration::from_millis(300);

    #[repr(C)]
    struct SecurityAttributes {
        length: Dword,
        security_descriptor: *mut c_void,
        inherit_handle: Bool,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: Dword,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: Dword,
        y: Dword,
        x_size: Dword,
        y_size: Dword,
        x_count_chars: Dword,
        y_count_chars: Dword,
        fill_attribute: Dword,
        flags: Dword,
        show_window: u16,
        reserved_2_size: u16,
        reserved_2: *mut u8,
        stdin: Handle,
        stdout: Handle,
        stderr: Handle,
    }

    #[repr(C)]
    struct StartupInfoExW {
        startup_info: StartupInfoW,
        attribute_list: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: Handle,
        thread: Handle,
        process_id: Dword,
        thread_id: Dword,
    }

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: Dword,
        minimum_working_set_size: SizeT,
        maximum_working_set_size: SizeT,
        active_process_limit: Dword,
        affinity: SizeT,
        priority_class: Dword,
        scheduling_class: Dword,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: SizeT,
        job_memory_limit: SizeT,
        peak_process_memory_used: SizeT,
        peak_job_memory_used: SizeT,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *mut SecurityAttributes, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            class: i32,
            info: *const c_void,
            length: Dword,
        ) -> Bool;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
        fn TerminateJobObject(job: Handle, exit_code: Dword) -> Bool;
        fn TerminateProcess(process: Handle, exit_code: Dword) -> Bool;
        fn CreatePipe(
            read: *mut Handle,
            write: *mut Handle,
            attributes: *mut SecurityAttributes,
            size: Dword,
        ) -> Bool;
        fn SetHandleInformation(handle: Handle, mask: Dword, flags: Dword) -> Bool;
        fn CreateFileW(
            name: *const u16,
            access: Dword,
            share_mode: Dword,
            attributes: *mut SecurityAttributes,
            creation_disposition: Dword,
            flags: Dword,
            template: Handle,
        ) -> Handle;
        fn InitializeProcThreadAttributeList(
            list: *mut c_void,
            count: Dword,
            flags: Dword,
            size: *mut SizeT,
        ) -> Bool;
        fn UpdateProcThreadAttribute(
            list: *mut c_void,
            flags: Dword,
            attribute: usize,
            value: *mut c_void,
            size: SizeT,
            previous_value: *mut c_void,
            return_size: *mut SizeT,
        ) -> Bool;
        fn DeleteProcThreadAttributeList(list: *mut c_void);
        fn CreateProcessW(
            application_name: *const u16,
            command_line: *mut u16,
            process_attributes: *mut SecurityAttributes,
            thread_attributes: *mut SecurityAttributes,
            inherit_handles: Bool,
            creation_flags: Dword,
            environment: *mut c_void,
            current_directory: *const u16,
            startup_info: *mut StartupInfoW,
            process_information: *mut ProcessInformation,
        ) -> Bool;
        fn ResumeThread(thread: Handle) -> Dword;
        fn WaitForSingleObject(handle: Handle, milliseconds: Dword) -> Dword;
        fn GetExitCodeProcess(process: Handle, exit_code: *mut Dword) -> Bool;
        fn GetStdHandle(which: Dword) -> Handle;
        fn GetLastError() -> Dword;
        fn ReadFile(
            handle: Handle,
            buffer: *mut c_void,
            bytes: Dword,
            read: *mut Dword,
            overlapped: *mut c_void,
        ) -> Bool;
        fn WriteFile(
            handle: Handle,
            buffer: *const c_void,
            bytes: Dword,
            written: *mut Dword,
            overlapped: *mut c_void,
        ) -> Bool;
        fn CloseHandle(handle: Handle) -> Bool;
    }

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn win32_error(operation: &str) -> String {
        format!("{operation} failed (Win32 error {})", unsafe {
            GetLastError()
        })
    }

    fn append_windows_arg(command_line: &mut Vec<u16>, argument: &OsStr) {
        let value: Vec<u16> = argument.encode_wide().collect();
        if !command_line.is_empty() {
            command_line.push(b' ' as u16);
        }
        let requires_quotes = value.is_empty()
            || value
                .iter()
                .any(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16 || *unit == b'"' as u16);
        if !requires_quotes {
            command_line.extend(value);
            return;
        }

        command_line.push(b'"' as u16);
        let mut backslashes = 0;
        for unit in value {
            if unit == b'\\' as u16 {
                backslashes += 1;
                continue;
            }
            if unit == b'"' as u16 {
                command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
                command_line.push(unit);
                backslashes = 0;
                continue;
            }
            command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            backslashes = 0;
            command_line.push(unit);
        }
        command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
        command_line.push(b'"' as u16);
    }

    fn command_line(application: &OsStr, arguments: impl Iterator<Item = OsString>) -> Vec<u16> {
        let mut result = Vec::new();
        append_windows_arg(&mut result, application);
        for argument in arguments {
            append_windows_arg(&mut result, &argument);
        }
        result.push(0);
        result
    }

    fn is_interactive_invocation(arguments: &[OsString]) -> bool {
        arguments.is_empty()
            || arguments.iter().all(|argument| {
                matches!(
                    argument.to_string_lossy().as_ref(),
                    "-i" | "-l" | "-il" | "-li" | "--login"
                )
            })
    }

    fn run_interactive(real_bash: &OsStr, arguments: &[OsString]) -> Result<i32, String> {
        let status = Command::new(real_bash)
            .args(arguments)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| format!("interactive real Bash launch failed: {error}"))?;
        Ok(status.code().unwrap_or(125))
    }

    unsafe fn close(handle: Handle) {
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(handle) };
        }
    }

    unsafe fn create_private_pipe() -> Result<(Handle, Handle), String> {
        let mut attributes = SecurityAttributes {
            length: size_of::<SecurityAttributes>() as Dword,
            security_descriptor: null_mut(),
            inherit_handle: TRUE,
        };
        let mut read = null_mut();
        let mut write = null_mut();
        if unsafe { CreatePipe(&mut read, &mut write, &mut attributes, 0) } == FALSE {
            return Err(win32_error("CreatePipe"));
        }
        if unsafe { SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0) } == FALSE {
            let error = win32_error("SetHandleInformation");
            unsafe {
                close(read);
                close(write);
            }
            return Err(error);
        }
        Ok((read, write))
    }

    unsafe fn open_null_stdin() -> Result<Handle, String> {
        let mut attributes = SecurityAttributes {
            length: size_of::<SecurityAttributes>() as Dword,
            security_descriptor: null_mut(),
            inherit_handle: TRUE,
        };
        let nul = wide_null(OsStr::new("NUL"));
        let handle = unsafe {
            CreateFileW(
                nul.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &mut attributes,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(win32_error("CreateFileW(NUL)"));
        }
        Ok(handle)
    }

    unsafe fn set_job_kill_on_close(job: Handle, enabled: bool) -> Result<(), String> {
        let mut info = JobObjectExtendedLimitInformation::default();
        if enabled {
            info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        if unsafe {
            SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                &info as *const _ as *const c_void,
                size_of::<JobObjectExtendedLimitInformation>() as Dword,
            )
        } == FALSE
        {
            return Err(win32_error("SetInformationJobObject"));
        }
        Ok(())
    }

    fn relay(read: Handle, output: Handle, finished: mpsc::Sender<()>) {
        let read_value = read as usize;
        let output_value = output as usize;
        thread::spawn(move || {
            let read = read_value as Handle;
            let output = output_value as Handle;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let mut count = 0;
                let ok = unsafe {
                    ReadFile(
                        read,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len() as Dword,
                        &mut count,
                        null_mut(),
                    )
                };
                if ok == FALSE || count == 0 {
                    break;
                }
                if output.is_null() || output == INVALID_HANDLE_VALUE {
                    continue;
                }
                let mut offset = 0_usize;
                while offset < count as usize {
                    let mut written = 0;
                    let ok = unsafe {
                        WriteFile(
                            output,
                            buffer[offset..count as usize].as_ptr() as *const c_void,
                            (count as usize - offset) as Dword,
                            &mut written,
                            null_mut(),
                        )
                    };
                    if ok == FALSE || written == 0 {
                        break;
                    }
                    offset += written as usize;
                }
            }
            unsafe { close(read) };
            let _ = finished.send(());
        });
    }

    pub fn run() -> Result<i32, String> {
        // The real Bash executable must be supplied by the caller via
        // OPENCODE_REAL_BASH; there is intentionally no machine-specific fallback so
        // the supervisor never silently targets the wrong shell. A missing value
        // is reported here and the existing main() flow exits with status 125.
        let real_bash = env::var_os("OPENCODE_REAL_BASH")
            .ok_or_else(|| String::from("OPENCODE_REAL_BASH is not set; cannot locate the real Bash executable"))?;
        let arguments: Vec<OsString> = env::args_os().skip(1).collect();
        if is_interactive_invocation(&arguments) {
            return run_interactive(&real_bash, &arguments);
        }
        let application = wide_null(&real_bash);
        let mut command = command_line(&real_bash, arguments.into_iter());

        let job = unsafe { CreateJobObjectW(null_mut(), null()) };
        if job.is_null() {
            return Err(win32_error("CreateJobObjectW"));
        }
        if let Err(error) = unsafe { set_job_kill_on_close(job, true) } {
            unsafe { close(job) };
            return Err(error);
        }

        let (stdout_read, stdout_write) = match unsafe { create_private_pipe() } {
            Ok(pipe) => pipe,
            Err(error) => {
                unsafe { close(job) };
                return Err(error);
            }
        };
        let (stderr_read, stderr_write) = match unsafe { create_private_pipe() } {
            Ok(pipe) => pipe,
            Err(error) => {
                unsafe {
                    close(stdout_read);
                    close(stdout_write);
                    close(job);
                }
                return Err(error);
            }
        };
        let null_stdin = match unsafe { open_null_stdin() } {
            Ok(handle) => handle,
            Err(error) => {
                unsafe {
                    close(stdout_read);
                    close(stdout_write);
                    close(stderr_read);
                    close(stderr_write);
                    close(job);
                }
                return Err(error);
            }
        };

        let mut attribute_size = 0_usize;
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attribute_size) };
        if attribute_size == 0 {
            let error = win32_error("InitializeProcThreadAttributeList(size query)");
            unsafe {
                close(null_stdin);
                close(stdout_read);
                close(stdout_write);
                close(stderr_read);
                close(stderr_write);
                close(job);
            }
            return Err(error);
        }
        let words = attribute_size.div_ceil(size_of::<usize>());
        let mut attribute_storage = vec![0_usize; words];
        let attribute_list = attribute_storage.as_mut_ptr() as *mut c_void;
        if unsafe { InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut attribute_size) }
            == FALSE
        {
            let error = win32_error("InitializeProcThreadAttributeList");
            unsafe {
                close(null_stdin);
                close(stdout_read);
                close(stdout_write);
                close(stderr_read);
                close(stderr_write);
                close(job);
            }
            return Err(error);
        }
        let mut inherited = [null_stdin, stdout_write, stderr_write];
        if unsafe {
            UpdateProcThreadAttribute(
                attribute_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inherited.as_mut_ptr() as *mut c_void,
                size_of::<Handle>() * inherited.len(),
                null_mut(),
                null_mut(),
            )
        } == FALSE
        {
            let error = win32_error("UpdateProcThreadAttribute(HANDLE_LIST)");
            unsafe {
                DeleteProcThreadAttributeList(attribute_list);
                close(null_stdin);
                close(stdout_read);
                close(stdout_write);
                close(stderr_read);
                close(stderr_write);
                close(job);
            }
            return Err(error);
        }

        let mut startup: StartupInfoExW = unsafe { zeroed() };
        startup.startup_info.cb = size_of::<StartupInfoExW>() as Dword;
        startup.startup_info.flags = STARTF_USESTDHANDLES;
        startup.startup_info.stdin = null_stdin;
        startup.startup_info.stdout = stdout_write;
        startup.startup_info.stderr = stderr_write;
        startup.attribute_list = attribute_list;
        let mut process: ProcessInformation = unsafe { zeroed() };
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null_mut(),
                null_mut(),
                TRUE,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                null_mut(),
                null(),
                &mut startup.startup_info,
                &mut process,
            )
        };
        let create_error = (created == FALSE).then(|| win32_error("CreateProcessW(real bash)"));
        unsafe { DeleteProcThreadAttributeList(attribute_list) };
        unsafe {
            close(null_stdin);
            close(stdout_write);
            close(stderr_write);
        }
        if created == FALSE {
            unsafe {
                close(stdout_read);
                close(stderr_read);
                close(job);
            }
            return Err(create_error.expect("failed process creation has an error"));
        }

        if unsafe { AssignProcessToJobObject(job, process.process) } == FALSE {
            let error = win32_error("AssignProcessToJobObject");
            unsafe {
                TerminateProcess(process.process, 125);
                WaitForSingleObject(process.process, 5_000);
                close(process.thread);
                close(process.process);
                close(stdout_read);
                close(stderr_read);
                close(job);
            }
            return Err(error);
        }
        if unsafe { ResumeThread(process.thread) } == Dword::MAX {
            let error = win32_error("ResumeThread");
            unsafe {
                TerminateJobObject(job, 125);
                WaitForSingleObject(process.process, 5_000);
                close(process.thread);
                close(process.process);
                close(stdout_read);
                close(stderr_read);
                close(job);
            }
            return Err(error);
        }

        let (finished_tx, finished_rx) = mpsc::channel();
        relay(
            stdout_read,
            unsafe { GetStdHandle(STD_OUTPUT_HANDLE) },
            finished_tx.clone(),
        );
        relay(
            stderr_read,
            unsafe { GetStdHandle(STD_ERROR_HANDLE) },
            finished_tx,
        );

        if unsafe { WaitForSingleObject(process.process, INFINITE) } != WAIT_OBJECT_0 {
            let error = win32_error("WaitForSingleObject");
            unsafe { TerminateJobObject(job, 125) };
            return Err(error);
        }
        let mut exit_code = STILL_ACTIVE;
        if unsafe { GetExitCodeProcess(process.process, &mut exit_code) } == FALSE {
            eprintln!(
                "opencode-bash-supervisor: {}",
                win32_error("GetExitCodeProcess")
            );
            exit_code = 125;
        }

        // Normal shell completion may intentionally leave a detached child alive.
        // Disable kill-on-close before releasing the job; forced supervisor death
        // never reaches this point, so its handle closure still kills the full job.
        let _ = unsafe { set_job_kill_on_close(job, false) };
        unsafe {
            close(process.thread);
            close(process.process);
            close(job);
        }

        let deadline = Instant::now() + DRAIN_GRACE;
        let mut finished = 0;
        while finished < 2 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            match finished_rx.recv_timeout(deadline - now) {
                Ok(()) => finished += 1,
                Err(_) => break,
            }
        }
        Ok(exit_code as i32)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn rendered(value: &[u16]) -> String {
            let end = value
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(value.len());
            String::from_utf16_lossy(&value[..end])
        }

        #[test]
        fn quotes_spaces_quotes_and_trailing_backslashes() {
            let args = [
                OsString::from("-lc"),
                OsString::from("printf '%s' \"a b\""),
                OsString::from(r"C:\path with space\"),
            ];
            let line = command_line(OsStr::new(r"C:\Program Files\bash.exe"), args.into_iter());
            assert_eq!(
                rendered(&line),
                r#""C:\Program Files\bash.exe" -lc "printf '%s' \"a b\"" "C:\path with space\\""#,
            );
        }

        #[test]
        fn recognizes_only_interactive_shell_argument_sets() {
            assert!(is_interactive_invocation(&[]));
            assert!(is_interactive_invocation(&[OsString::from("-l")]));
            assert!(is_interactive_invocation(&[
                OsString::from("-i"),
                OsString::from("--login"),
            ]));
            assert!(!is_interactive_invocation(&[
                OsString::from("-c"),
                OsString::from("echo ok"),
            ]));
            assert!(!is_interactive_invocation(&[
                OsString::from("-lc"),
                OsString::from("echo ok"),
            ]));
        }
    }
}

#[cfg(windows)]
fn main() {
    match windows::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("opencode-bash-supervisor: {error}");
            std::process::exit(125);
        }
    }
}
