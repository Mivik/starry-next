use core::ffi::{c_char, c_void};

use arceos_posix_api::{AT_FDCWD, with_fs};
use axerrno::{LinuxError, LinuxResult};
use axfs_ng_vfs::{DirEntry, NodePermission, NodeType};
use axsync::RawMutex;
use linux_raw_sys::general::AT_REMOVEDIR;
use macro_rules_attribute::apply;

use crate::{
    ptr::{PtrWrapper, UserConstPtr, UserPtr},
    syscall_instrument,
};

/// The ioctl() system call manipulates the underlying device parameters
/// of special files.
///
/// # Arguments
/// * `fd` - The file descriptor
/// * `op` - The request code. It is of type unsigned long in glibc and BSD,
///   and of type int in musl and other UNIX systems.
/// * `argp` - The argument to the request. It is a pointer to a memory location
#[apply(syscall_instrument)]
pub fn sys_ioctl(_fd: i32, _op: usize, _argp: UserPtr<c_void>) -> LinuxResult<isize> {
    warn!("Unimplemented syscall: SYS_IOCTL");
    Ok(0)
}

pub fn sys_chdir(path: UserConstPtr<c_char>) -> LinuxResult<isize> {
    let path = path.get_as_str()?;
    arceos_posix_api::with_fs(AT_FDCWD, |fs| {
        let entry = fs.resolve(path)?;
        fs.set_current_dir(entry)?;
        Ok(0)
    })
    .inspect_err(|err| {
        warn!("Failed to change directory: {err:?}");
    })
}

pub fn sys_mkdirat(dirfd: i32, path: UserConstPtr<c_char>, mode: u32) -> LinuxResult<isize> {
    let path = path.get_as_str()?;
    let mode = NodePermission::from_bits(mode as u16).ok_or(LinuxError::EINVAL)?;

    with_fs(dirfd, |fs| {
        fs.create_dir(path, mode)?;
        Ok(0)
    })
    .inspect_err(|err| {
        warn!("Failed to create directory {path}: {err:?}");
    })
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DirEnt {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    d_name: [u8; 0],
}

impl DirEnt {
    const FIXED_SIZE: usize = core::mem::size_of::<u64>()
        + core::mem::size_of::<i64>()
        + core::mem::size_of::<u16>()
        + core::mem::size_of::<u8>();

    fn new(ino: u64, off: i64, reclen: usize, file_type: NodeType) -> Self {
        Self {
            d_ino: ino,
            d_off: off,
            d_reclen: reclen as u16,
            d_type: file_type as u8,
            d_name: [],
        }
    }

    unsafe fn write_name(&mut self, name: &[u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(name.as_ptr(), self.d_name.as_mut_ptr(), name.len());
            self.d_name.as_mut_ptr().add(name.len()).write(0);
        }
    }
}

// Directory buffer for getdents64 syscall
struct DirBuffer<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> DirBuffer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn remaining_space(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    fn can_fit_entry(&self, entry_size: usize) -> bool {
        self.remaining_space() >= entry_size
    }

    fn write_entry(&mut self, dirent: DirEnt, name: &[u8]) -> Result<(), ()> {
        if !self.can_fit_entry(dirent.d_reclen as usize) {
            return Err(());
        }
        unsafe {
            let entry_ptr = self.buf.as_mut_ptr().add(self.offset) as *mut DirEnt;
            entry_ptr.write(dirent);
            (*entry_ptr).write_name(name);
        }

        self.offset += dirent.d_reclen as usize;
        Ok(())
    }
}

pub fn sys_getdents64(fd: i32, buf: UserPtr<c_void>, len: usize) -> LinuxResult<isize> {
    let buf = buf.get_as_bytes(len)?;

    if len < DirEnt::FIXED_SIZE {
        warn!("Buffer size too small: {len}");
        return Err(LinuxError::EINVAL);
    }

    let mut buffer =
        unsafe { DirBuffer::new(core::slice::from_raw_parts_mut(buf as *mut u8, len)) };

    let dir = arceos_posix_api::Directory::from_fd(fd)?;
    let offset = dir.offset.lock();

    let mut count = 0;
    let mut dir_offset = 0;
    dir.inner()
        .as_dir()?
        .read_dir(*offset, &mut |entry: DirEntry<RawMutex>, offset| {
            let name = entry.name();
            let entry_size = DirEnt::FIXED_SIZE + name.len() + 1;
            if !buffer.can_fit_entry(entry_size) {
                return false;
            }

            let dirent = DirEnt::new(entry.inode(), offset as _, entry_size, entry.node_type());

            if buffer.write_entry(dirent, name.as_bytes()).is_err() {
                return false;
            }

            dir_offset += entry_size as i64;
            count += 1;
            true
        })?;
    Ok(count)
}

/// create a link from new_path to old_path
/// old_path: old file path
/// new_path: new file path
/// flags: link flags
/// return value: return 0 when success, else return -1.
pub fn sys_linkat(
    old_dirfd: i32,
    old_path: UserConstPtr<c_char>,
    new_dirfd: i32,
    new_path: UserConstPtr<c_char>,
    flags: i32,
) -> LinuxResult<isize> {
    let old_path = old_path.get_as_str()?;
    let new_path = new_path.get_as_str()?;

    if flags != 0 {
        warn!("Unsupported flags: {flags}");
    }

    let old = with_fs(old_dirfd, |fs| Ok(fs.resolve(old_path)?))?;
    let (new_dir, new_name) =
        with_fs(new_dirfd, |fs| Ok(fs.resolve_nonexistent(new_path.into())?))?;

    new_dir.as_dir()?.link(new_name, &old)?;
    Ok(0)
}

/// remove link of specific file (can be used to delete file)
/// dir_fd: the directory of link to be removed
/// path: the name of link to be removed
/// flags: can be 0 or AT_REMOVEDIR
/// return 0 when success, else return -1
pub fn sys_unlinkat(dirfd: i32, path: UserConstPtr<c_char>, flags: usize) -> LinuxResult<isize> {
    let path = path.get_as_str()?;

    with_fs(dirfd, |fs| {
        if flags == AT_REMOVEDIR as _ {
            fs.remove_dir(path)?;
        } else {
            fs.remove_file(path)?;
        }
        Ok(0)
    })
}

pub fn sys_getcwd(buf: UserPtr<c_char>, size: usize) -> LinuxResult<isize> {
    Ok(arceos_posix_api::sys_getcwd(buf.get_as_null_terminated()?.as_ptr() as _, size) as _)
}
