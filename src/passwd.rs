/// POSIX password and group database lookups via libc.
use std::ffi::{CStr, CString};
use std::sync::Mutex;

// setpwent/getpwent and setgrent/getgrent use global state
// and are not thread-safe.
static DB_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home_dir: String,
    pub shell: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

pub fn get_user_by_name(name: &str) -> Option<User> {
    let cname = CString::new(name).ok()?;
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buf = vec![0u8; 1024];
    loop {
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            return if result.is_null() {
                None
            } else {
                Some(unsafe { passwd_to_user(&*result) })
            };
        }
        if rc == libc::ERANGE && buf.len() < 64 * 1024 {
            buf.resize(buf.len() * 2, 0);
        } else {
            return None;
        }
    }
}

pub fn get_all_users() -> Vec<User> {
    let _guard = DB_LOCK.lock().unwrap();
    let mut users = Vec::new();
    unsafe {
        libc::setpwent();
        loop {
            let pw = libc::getpwent();
            if pw.is_null() { break; }
            users.push(passwd_to_user(&*pw));
        }
        libc::endpwent();
    }
    users
}

pub fn get_all_groups() -> Vec<Group> {
    let _guard = DB_LOCK.lock().unwrap();
    let mut groups = Vec::new();
    unsafe {
        libc::setgrent();
        loop {
            let gr = libc::getgrent();
            if gr.is_null() { break; }
            groups.push(group_to_group(&*gr));
        }
        libc::endgrent();
    }
    groups
}

unsafe fn passwd_to_user(pw: &libc::passwd) -> User {
    User {
        name: unsafe { cstr(pw.pw_name) },
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        gecos: unsafe { cstr(pw.pw_gecos) },
        home_dir: unsafe { cstr(pw.pw_dir) },
        shell: unsafe { cstr(pw.pw_shell) },
    }
}

unsafe fn group_to_group(gr: &libc::group) -> Group {
    let mut members = Vec::new();
    if !gr.gr_mem.is_null() {
        let mut i = 0;
        loop {
            let ptr = unsafe { *gr.gr_mem.add(i) };
            if ptr.is_null() { break; }
            members.push(unsafe { cstr(ptr) });
            i += 1;
        }
    }
    Group {
        name: unsafe { cstr(gr.gr_name) },
        gid: gr.gr_gid,
        members,
    }
}

unsafe fn cstr(ptr: *const libc::c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
    }
}
