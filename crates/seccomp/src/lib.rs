#![forbid(unsafe_code)]
//! seccomp(2) filters: classic BPF programs that judge each system call
//! from its number, architecture, instruction pointer and arguments.
//!
//! `Program::new` checks a program as Linux's `seccomp_check_filter` and
//! `bpf_check_classic` do (only the instructions seccomp allows, loads of
//! `struct seccomp_data` words, jumps inside the program, no constant
//! division by zero, a return at the end), and `Program::run` interprets
//! it. A process's filters form a chain whose strictest answer wins
//! (`strictest`), and `Verdict::from_return` says what that answer means.
//!
//! This is pure computation, so it is tested on the host; the kernel keeps
//! the chains and acts on the verdicts.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// The most instructions one program may have (BPF_MAXINSNS).
pub const MAX_INSTRUCTIONS: usize = 4096;
/// The size of `struct seccomp_data`: nr, arch, instruction_pointer and
/// six arguments.
pub const DATA_SIZE: u32 = 64;
/// AUDIT_ARCH_X86_64, the `arch` field of every x86-64 system call.
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// The return values' actions, strictest first.
pub mod action {
    pub const KILL_PROCESS: u32 = 0x8000_0000;
    pub const KILL_THREAD: u32 = 0x0000_0000;
    pub const TRAP: u32 = 0x0003_0000;
    pub const ERRNO: u32 = 0x0005_0000;
    pub const USER_NOTIF: u32 = 0x7fc0_0000;
    pub const TRACE: u32 = 0x7ff0_0000;
    pub const LOG: u32 = 0x7ffc_0000;
    pub const ALLOW: u32 = 0x7fff_0000;
    /// The action part of a return value.
    pub const FULL_MASK: u32 = 0xffff_0000;
    /// The data part (an errno, a trap's si_errno).
    pub const DATA_MASK: u32 = 0x0000_ffff;
}

/// One `struct sock_filter`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instruction {
    pub code: u16,
    pub jump_true: u8,
    pub jump_false: u8,
    pub k: u32,
}

impl Instruction {
    /// Reads one instruction as user memory holds it.
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            code: u16::from_ne_bytes([bytes[0], bytes[1]]),
            jump_true: bytes[2],
            jump_false: bytes[3],
            k: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }
}

/// What a filter sees of a system call (`struct seccomp_data`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Data {
    pub number: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub arguments: [u64; 6],
}

impl Data {
    /// The 32-bit word at byte `offset`, as BPF_LD|BPF_W|BPF_ABS reads it.
    fn word(&self, offset: u32) -> u32 {
        let wide = |value: u64, high: bool| {
            if high {
                (value >> 32) as u32
            } else {
                value as u32
            }
        };
        match offset {
            0 => self.number as u32,
            4 => self.arch,
            8 | 12 => wide(self.instruction_pointer, offset == 12),
            16..=60 => {
                let index = (offset as usize - 16) / 8;
                wide(self.arguments[index], offset % 8 == 4)
            }
            _ => 0,
        }
    }
}

/// A program Linux would refuse (EINVAL).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Invalid;

// Instruction classes, sizes, modes, operations and sources.
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;
const W: u16 = 0x00;
const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const MEM: u16 = 0x60;
const LEN: u16 = 0x80;
const ADD: u16 = 0x00;
const SUB: u16 = 0x10;
const MUL: u16 = 0x20;
const DIV: u16 = 0x30;
const OR: u16 = 0x40;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const RSH: u16 = 0x70;
const NEG: u16 = 0x80;
const MOD: u16 = 0x90;
const XOR: u16 = 0xa0;
const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JGT: u16 = 0x20;
const JGE: u16 = 0x30;
const JSET: u16 = 0x40;
const K: u16 = 0x00;
const X: u16 = 0x08;
const RET_A: u16 = 0x10;
const TAX: u16 = 0x00;
const TXA: u16 = 0x80;
/// The scratch memory words (BPF_MEMWORDS).
const MEMORY_WORDS: u32 = 16;

/// A checked program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    instructions: Vec<Instruction>,
}

impl Program {
    /// Checks `instructions` as Linux does before installing a filter.
    /// Loads of the data's length become loads of its size, as in Linux.
    pub fn new(mut instructions: Vec<Instruction>) -> Result<Self, Invalid> {
        let count = instructions.len();
        if count == 0 || count > MAX_INSTRUCTIONS {
            return Err(Invalid);
        }
        for (index, instruction) in instructions.iter_mut().enumerate() {
            let code = instruction.code;
            let k = instruction.k;
            let class = code & 0x07;
            let valid = match code {
                c if c == LD | W | ABS => k % 4 == 0 && k < DATA_SIZE,
                c if c == LD | W | LEN || c == LDX | W | LEN => {
                    instruction.code = class | IMM;
                    instruction.k = DATA_SIZE;
                    true
                }
                c if c == LD | IMM || c == LDX | IMM => true,
                c if c == LD | MEM || c == LDX | MEM || c == ST || c == STX => k < MEMORY_WORDS,
                c if c == RET | K || c == RET | RET_A => true,
                c if c == MISC | TAX || c == MISC | TXA => true,
                c if class == ALU => match c & 0xf0 {
                    NEG => c & X == 0,
                    DIV | MOD => c & X != 0 || k != 0,
                    LSH | RSH => c & X != 0 || k < 32,
                    ADD | SUB | MUL | OR | AND | XOR => true,
                    _ => false,
                },
                c if class == JMP => {
                    let next = index + 1;
                    match c & 0xf0 {
                        JA => c & X == 0 && (k as usize) < count - next,
                        JEQ | JGT | JGE | JSET => {
                            next + usize::from(instruction.jump_true) < count
                                && next + usize::from(instruction.jump_false) < count
                        }
                        _ => false,
                    }
                }
                _ => false,
            };
            if !valid {
                return Err(Invalid);
            }
        }
        if instructions[count - 1].code & 0x07 != RET {
            return Err(Invalid);
        }
        Ok(Self { instructions })
    }

    /// The number of instructions, for the chain's total limit.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Whether the program is empty (never, once checked).
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Runs the program on `data` and returns its return value.
    pub fn run(&self, data: &Data) -> u32 {
        let mut a = 0_u32;
        let mut x = 0_u32;
        let mut memory = [0_u32; MEMORY_WORDS as usize];
        let mut pc = 0;
        while let Some(instruction) = self.instructions.get(pc) {
            pc += 1;
            let code = instruction.code;
            let k = instruction.k;
            let source = if code & X != 0 { x } else { k };
            match code & 0x07 {
                LD => {
                    a = match code & 0xe0 {
                        ABS => data.word(k),
                        MEM => memory[k as usize],
                        _ => k,
                    }
                }
                LDX => {
                    x = if code & 0xe0 == MEM {
                        memory[k as usize]
                    } else {
                        k
                    }
                }
                ST => memory[k as usize] = a,
                STX => memory[k as usize] = x,
                ALU => {
                    a = match code & 0xf0 {
                        ADD => a.wrapping_add(source),
                        SUB => a.wrapping_sub(source),
                        MUL => a.wrapping_mul(source),
                        DIV => a.checked_div(source).unwrap_or(0),
                        MOD => a.checked_rem(source).unwrap_or(0),
                        OR => a | source,
                        AND => a & source,
                        XOR => a ^ source,
                        LSH => a.checked_shl(source).unwrap_or(0),
                        RSH => a.checked_shr(source).unwrap_or(0),
                        _ => a.wrapping_neg(),
                    }
                }
                JMP => {
                    let offset = match code & 0xf0 {
                        JA => k as usize,
                        operation => {
                            let taken = match operation {
                                JEQ => a == source,
                                JGT => a > source,
                                JGE => a >= source,
                                _ => a & source != 0,
                            };
                            usize::from(if taken {
                                instruction.jump_true
                            } else {
                                instruction.jump_false
                            })
                        }
                    };
                    pc += offset;
                }
                RET => return if code & RET_A != 0 { a } else { k },
                _ => {
                    if code & TXA != 0 {
                        a = x;
                    } else {
                        x = a;
                    }
                }
            }
        }
        // A checked program ends in a return; this is not reached.
        action::KILL_PROCESS
    }
}

/// Of two return values, the one whose action is stricter (Linux compares
/// the actions as signed numbers: KILL_PROCESS first, ALLOW last).
pub fn strictest(first: u32, second: u32) -> u32 {
    let rank = |value: u32| (value & action::FULL_MASK) as i32;
    if rank(second) < rank(first) {
        second
    } else {
        first
    }
}

/// What a return value asks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    KillProcess,
    KillThread,
    /// SIGSYS, with this si_errno.
    Trap(u16),
    /// Fail the call with this errno.
    Errno(u16),
    /// A user-space supervisor or tracer would decide; with none, ENOSYS.
    NoHandler,
    /// Allow, and log it.
    Log,
    Allow,
}

impl Verdict {
    pub fn from_return(value: u32) -> Self {
        let data = (value & action::DATA_MASK) as u16;
        match value & action::FULL_MASK {
            action::KILL_PROCESS => Self::KillProcess,
            action::KILL_THREAD => Self::KillThread,
            action::TRAP => Self::Trap(data),
            action::ERRNO => Self::Errno(data.min(4095)),
            action::USER_NOTIF | action::TRACE => Self::NoHandler,
            action::LOG => Self::Log,
            action::ALLOW => Self::Allow,
            // An unknown action is treated as KILL_PROCESS, as Linux does.
            _ => Self::KillProcess,
        }
    }
}

/// Whether SECCOMP_GET_ACTION_AVAIL reports `value` as known.
pub fn action_available(value: u32) -> bool {
    matches!(
        value,
        action::KILL_PROCESS
            | action::KILL_THREAD
            | action::TRAP
            | action::ERRNO
            | action::USER_NOTIF
            | action::TRACE
            | action::LOG
            | action::ALLOW
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn statement(code: u16, k: u32) -> Instruction {
        Instruction {
            code,
            jump_true: 0,
            jump_false: 0,
            k,
        }
    }

    fn jump(code: u16, k: u32, jump_true: u8, jump_false: u8) -> Instruction {
        Instruction {
            code,
            jump_true,
            jump_false,
            k,
        }
    }

    fn call(number: i32, arguments: [u64; 6]) -> Data {
        Data {
            number,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0x1234_5678_9abc,
            arguments,
        }
    }

    #[test]
    fn allow_list_like_seccomp01() {
        // Allows close (3) and write (1); kills the rest.
        let program = Program::new(vec![
            statement(LD | W | ABS, 0),
            jump(JMP | JEQ | K, 3, 1, 0),
            jump(JMP | JEQ | K, 1, 0, 1),
            statement(RET | K, action::ALLOW),
            statement(RET | K, action::KILL_THREAD),
        ])
        .unwrap();
        assert_eq!(program.run(&call(3, [0; 6])), action::ALLOW);
        assert_eq!(program.run(&call(1, [0; 6])), action::ALLOW);
        assert_eq!(program.run(&call(157, [0; 6])), action::KILL_THREAD);
    }

    #[test]
    fn arguments_memory_and_arithmetic() {
        // Returns ERRNO with (arg0 high word + arg1 low word) & 0xff.
        let program = Program::new(vec![
            statement(LD | W | ABS, 20),
            statement(ST, 3),
            statement(LD | W | ABS, 24),
            statement(MISC | TAX, 0),
            statement(LD | MEM, 3),
            statement(ALU | ADD | X, 0),
            statement(ALU | AND | K, 0xff),
            statement(ALU | OR | K, action::ERRNO),
            statement(RET | RET_A, 0),
        ])
        .unwrap();
        let data = call(0, [5 << 32, 7, 0, 0, 0, 0]);
        assert_eq!(program.run(&data), action::ERRNO | 12);
        assert_eq!(Verdict::from_return(program.run(&data)), Verdict::Errno(12));
    }

    #[test]
    fn length_loads_and_runtime_division() {
        let program = Program::new(vec![
            statement(LD | W | LEN, 0),
            statement(LDX | IMM, 0),
            statement(ALU | DIV | X, 0),
            statement(RET | RET_A, 0),
        ])
        .unwrap();
        assert_eq!(program.run(&call(0, [0; 6])), 0);
        let size =
            Program::new(vec![statement(LD | W | LEN, 0), statement(RET | RET_A, 0)]).unwrap();
        assert_eq!(size.run(&call(0, [0; 6])), DATA_SIZE);
    }

    #[test]
    fn refuses_what_linux_refuses() {
        let ret = statement(RET | K, action::ALLOW);
        assert_eq!(Program::new(vec![]), Err(Invalid));
        assert_eq!(
            Program::new(vec![statement(LD | W | ABS, 2), ret]),
            Err(Invalid)
        );
        assert_eq!(
            Program::new(vec![statement(LD | W | ABS, 64), ret]),
            Err(Invalid)
        );
        assert_eq!(
            Program::new(vec![statement(ALU | DIV | K, 0), ret]),
            Err(Invalid)
        );
        assert_eq!(Program::new(vec![statement(ST, 16), ret]), Err(Invalid));
        assert_eq!(
            Program::new(vec![jump(JMP | JEQ | K, 0, 1, 0), ret]),
            Err(Invalid)
        );
        assert_eq!(Program::new(vec![statement(LD | IMM, 0)]), Err(Invalid));
        // BPF_LD|BPF_H|BPF_ABS: halfword loads are not allowed.
        assert_eq!(Program::new(vec![statement(0x28, 0), ret]), Err(Invalid));
        assert_eq!(Program::new(vec![ret; MAX_INSTRUCTIONS + 1]), Err(Invalid));
        assert!(Program::new(vec![jump(JMP | JA, 0, 0, 0), ret]).is_ok());
    }

    #[test]
    fn strictest_action_wins() {
        assert_eq!(
            strictest(action::ALLOW, action::ERRNO | 1),
            action::ERRNO | 1
        );
        assert_eq!(
            strictest(action::KILL_THREAD, action::TRAP),
            action::KILL_THREAD
        );
        assert_eq!(
            strictest(action::KILL_THREAD, action::KILL_PROCESS),
            action::KILL_PROCESS
        );
        assert_eq!(strictest(action::LOG, action::ALLOW), action::LOG);
        assert_eq!(Verdict::from_return(0x1234_0000), Verdict::KillProcess);
        assert!(action_available(action::LOG));
        assert!(!action_available(0x1234_0000));
    }
}
