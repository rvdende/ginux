//! Where composed frames go: the Linux framebuffer device (/dev/fb0) or an
//! in-memory buffer for headless runs, both of which can be saved as PPM.

use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::fd::AsRawFd,
    path::Path,
};

extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
}

const FBIOGET_VSCREENINFO: u64 = 0x4600;
const FBIOGET_FSCREENINFO: u64 = 0x4602;

pub trait Output {
    fn size(&self) -> (i32, i32);
    fn present(&mut self, frame: &[u32]);
}

/// The kernel's fbdev interface: the frame is copied into the mapped
/// framebuffer, converting to its channel layout when that is not XRGB.
pub struct Framebuffer {
    _file: File,
    base: *mut u8,
    width: i32,
    height: i32,
    stride: usize,
    shifts: (u32, u32, u32),
}

impl Framebuffer {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut variable = [0_u32; 40];
        let mut fixed = [0_u8; 80];
        // SAFETY: both ioctls fill a buffer of their structure's size.
        unsafe {
            if ioctl(file.as_raw_fd(), FBIOGET_VSCREENINFO, variable.as_mut_ptr()) != 0
                || ioctl(file.as_raw_fd(), FBIOGET_FSCREENINFO, fixed.as_mut_ptr()) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        // fb_var_screeninfo: xres, yres, xres_virtual, yres_virtual, xoffset,
        // yoffset, bits_per_pixel, grayscale, then red/green/blue bitfields
        // of (offset, length, msb_right).
        let (width, height, bits) = (variable[0], variable[1], variable[6]);
        if bits != 32 {
            return Err(io::Error::other(format!(
                "{bits} bits per pixel is not supported"
            )));
        }
        let shifts = (variable[8], variable[11], variable[14]);
        let length = u32::from_ne_bytes(fixed[24..28].try_into().unwrap()) as usize;
        let stride = u32::from_ne_bytes(fixed[48..52].try_into().unwrap()) as usize;
        if stride < width as usize * 4 || length < stride * height as usize {
            return Err(io::Error::other("framebuffer geometry is inconsistent"));
        }
        // SAFETY: maps the device's framebuffer memory, which stays mapped
        // for the life of the process.
        let base = unsafe { mmap(std::ptr::null_mut(), length, 3, 1, file.as_raw_fd(), 0) };
        if base as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _file: file,
            base: base.cast(),
            width: width as i32,
            height: height as i32,
            stride,
            shifts,
        })
    }
}

impl Output for Framebuffer {
    fn size(&self) -> (i32, i32) {
        (self.width, self.height)
    }

    fn present(&mut self, frame: &[u32]) {
        let width = self.width as usize;
        let native = self.shifts == (16, 8, 0);
        for (row, pixels) in frame
            .chunks_exact(width)
            .take(self.height as usize)
            .enumerate()
        {
            // SAFETY: each row lies inside the mapping checked in open().
            let target = unsafe {
                std::slice::from_raw_parts_mut(
                    self.base.add(row * self.stride).cast::<u32>(),
                    width,
                )
            };
            if native {
                target.copy_from_slice(pixels);
            } else {
                let (red, green, blue) = self.shifts;
                for (target, pixel) in target.iter_mut().zip(pixels) {
                    *target = ((pixel >> 16) & 0xff) << red
                        | ((pixel >> 8) & 0xff) << green
                        | (pixel & 0xff) << blue;
                }
            }
        }
    }
}

/// Keeps nothing but the size; frames are saved from the compositor's own
/// buffer when a screenshot is requested.
pub struct Headless {
    pub width: i32,
    pub height: i32,
}

impl Output for Headless {
    fn size(&self) -> (i32, i32) {
        (self.width, self.height)
    }

    fn present(&mut self, _frame: &[u32]) {}
}

pub fn save_ppm(path: &Path, frame: &[u32], width: i32, height: i32) -> io::Result<()> {
    let mut bytes = format!("P6\n{width} {height}\n255\n").into_bytes();
    for pixel in frame.iter().take((width * height) as usize) {
        bytes.extend_from_slice(&[(pixel >> 16) as u8, (pixel >> 8) as u8, *pixel as u8]);
    }
    File::create(path)?.write_all(&bytes)
}
