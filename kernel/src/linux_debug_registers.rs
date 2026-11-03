//! The x86 debug registers a tracer reads and writes through
//! PTRACE_PEEKUSER and PTRACE_POKEUSER (`struct user`'s `u_debugreg`):
//! DR0-DR3 hold breakpoint addresses, DR6 the status, DR7 the control.
//!
//! Each address register holds a breakpoint once written (or once DR7
//! enables it), and every write is checked as Linux checks a ptrace
//! breakpoint: the range must not wrap, must be aligned to its length and
//! must lie wholly in user space, and DR7 may only name execute, write and
//! read/write breakpoints of 1, 2, 4 or 8 bytes. A refused write changes
//! nothing (EINVAL), so a kernel address can never be read back.
//!
//! The values are the tracee's, kept with its process; they are not loaded
//! into the CPU's debug registers, so a breakpoint set this way does not
//! trap yet.
#![forbid(unsafe_code)]

/// The first address above user space a breakpoint may not reach: Linux's
/// TASK_SIZE_MAX with four-level paging.
const USER_SPACE_END: u64 = (1 << 47) - 4096;
/// DR6 bits that read as one, as Linux reports an untouched status.
const STATUS_RESERVED: u64 = 0xffff_0ff0;
/// DR7 bits that select no breakpoint and are ignored on a write.
const CONTROL_RESERVED: u64 = 0xffff_ffff_0000_fc00;

/// A write the registers refuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The breakpoint it describes is not allowed (EINVAL).
    Invalid,
    /// DR4 and DR5 do not exist (EIO).
    NoRegister,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Execute,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Breakpoint {
    address: u64,
    length: u64,
    access: Access,
}

impl Breakpoint {
    /// A breakpoint for an address written before DR7 describes it: one
    /// byte, on writes, as Linux creates an inactive one.
    const fn unconfigured(address: u64) -> Self {
        Self {
            address,
            length: 1,
            access: Access::Write,
        }
    }

    /// DR7's four bits for one breakpoint: the access in the low two, the
    /// length in the high two (an execute breakpoint has length bits 0 and
    /// covers an instruction, which Linux counts as eight bytes).
    fn configured(address: u64, bits: u64) -> Result<Self, Error> {
        let access = match bits & 3 {
            0 if bits & 0xc == 0 => Access::Execute,
            1 => Access::Write,
            3 => Access::ReadWrite,
            _ => return Err(Error::Invalid),
        };
        let length = match (access, bits & 0xc) {
            (Access::Execute, _) => 8,
            (_, 0x0) => 1,
            (_, 0x4) => 2,
            (_, 0xc) => 4,
            _ => 8,
        };
        Ok(Self {
            address,
            length,
            access,
        })
    }

    fn check(self) -> Result<Self, Error> {
        let end = self
            .address
            .checked_add(self.length - 1)
            .ok_or(Error::Invalid)?;
        // An instruction breakpoint has no alignment and reaches one byte.
        let (alignment, last) = match self.access {
            Access::Execute => (1, self.address),
            _ => (self.length, end),
        };
        if !self.address.is_multiple_of(alignment) || last >= USER_SPACE_END {
            return Err(Error::Invalid);
        }
        Ok(self)
    }
}

/// One tracee's debug registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DebugRegisters {
    breakpoints: [Option<Breakpoint>; 4],
    status: u64,
    control: u64,
}

impl DebugRegisters {
    /// A new process's (and one that executed a program): no breakpoints.
    pub(crate) const RESET: Self = Self {
        breakpoints: [None; 4],
        status: STATUS_RESERVED,
        control: 0,
    };

    /// Register `index` (0-7) as PTRACE_PEEKUSER reads it: an address
    /// register without a breakpoint, DR4 and DR5 read as 0.
    pub(crate) fn read(&self, index: usize) -> u64 {
        match index {
            0..=3 => self.breakpoints[index].map_or(0, |breakpoint| breakpoint.address),
            6 => self.status,
            7 => self.control,
            _ => 0,
        }
    }

    /// Writes register `index` (0-7), all or nothing.
    pub(crate) fn write(&mut self, index: usize, value: u64) -> Result<(), Error> {
        match index {
            0..=3 => {
                let breakpoint =
                    self.breakpoints[index].map_or(Breakpoint::unconfigured(value), |breakpoint| {
                        Breakpoint {
                            address: value,
                            ..breakpoint
                        }
                    });
                self.breakpoints[index] = Some(breakpoint.check()?);
            }
            6 => self.status = value,
            7 => {
                let control = value & !CONTROL_RESERVED;
                let mut breakpoints = self.breakpoints;
                for (number, slot) in breakpoints.iter_mut().enumerate() {
                    let enabled = control >> (2 * number) & 3 != 0;
                    if slot.is_none() && !enabled {
                        continue;
                    }
                    let address = slot.map_or(0, |breakpoint| breakpoint.address);
                    let bits = control >> (16 + 4 * number) & 0xf;
                    *slot = Some(Breakpoint::configured(address, bits)?.check()?);
                }
                self.breakpoints = breakpoints;
                self.control = value;
            }
            _ => return Err(Error::NoRegister),
        }
        Ok(())
    }
}
