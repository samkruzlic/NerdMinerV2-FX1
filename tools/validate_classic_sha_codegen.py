"""Execute emitted Xtensa kernel instructions against a strict SHA MMIO model.

This is an instruction-level host model, NOT an ESP32 emulator or hardware
benchmark. It checks register allocation, byte order, padding, the idle-before-
write contract, protected DPORT reads, and the actual compiled early filter.
"""
import argparse
import hashlib
import random
import re
import struct
import subprocess
from pathlib import Path


def output(command):
    return subprocess.check_output(command, text=True)


class Kernel:
    TEXT = 0x3ff03000
    GROUP = 1024          # CLASSIC_SHA_GROUP_NONCES
    WRITES_PER_NONCE = 34  # 16 + 16 + words 8 and 15 of the block-3 padding
    FULL_PADDING_WRITES = 40  # fallback selected by the boot known-answer test
    CYCLES_PER_INSTRUCTION = 4  # rough, only to give the modelled timer realistic spacing
    APB = 0x3ff40078

    def __init__(self, elf, toolchain):
        self.image = elf.read_bytes()
        h = struct.unpack('<16sHHIIIIIHHHHHH', self.image[:52])
        self.sections = []
        for i in range(h[12]):
            s = struct.unpack_from('<10I', self.image, h[6] + i * h[11])
            if s[1] == 1:
                self.sections.append((s[3], s[4], s[5]))
        nm = output([str(toolchain / 'xtensa-esp32-elf-nm.exe'), '-S', '-C', str(elf)])
        self.names = {}
        self.statics = {}
        helper_ranges = []
        for line in nm.splitlines():
            parts = line.split(maxsplit=3)
            if len(parts) == 3 and re.fullmatch('[0-9a-f]+', parts[0]):
                self.names[int(parts[0], 16)] = parts[2]
            if len(parts) == 4:
                self.names[int(parts[0], 16)] = parts[3]
                if 'runClassicHardwareSequential(' in parts[3]:
                    self.start = int(parts[0], 16)
                    self.size = int(parts[1], 16)
                if 's_working_generation' in parts[3]:
                    self.generation = int(parts[0], 16)
                if parts[3] == 's_classic_full_padding':
                    self.statics['s_classic_full_padding'] = int(parts[0], 16)
                for static in ('secureTransportCpuSessions()::sessions',
                               'secureTransportHandshakeSessions()::sessions',
                               'shaCpuWindowMicroseconds()::value',
                               'shaHandshakeWindowMicroseconds()::value'):
                    if parts[3] == static:
                        self.statics[static] = int(parts[0], 16)
                if 'recordHardwareCandidate(' in parts[3]:
                    helper_ranges.append((int(parts[0], 16), int(parts[1], 16)))
        listing = output([str(toolchain / 'xtensa-esp32-elf-objdump.exe'), '-d', '-C',
                          f'--start-address={self.start}',
                          f'--stop-address={self.start + self.size}', str(elf)])
        for address, size in helper_ranges:
            listing += output([str(toolchain / 'xtensa-esp32-elf-objdump.exe'), '-d', '-C',
                               f'--start-address={address}', f'--stop-address={address + size}', str(elf)])
        self.code = {}
        for line in listing.splitlines():
            m = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*)', line)
            if m and m[3] != '.byte':
                self.code[int(m[1], 16)] = (m[3].removesuffix('.n'),
                    [p.strip() for p in m[4].split('<')[0].split(',') if p.strip()],
                    len(m[2]) // 2)

    def read(self, address):
        if address == self.APB:
            self.preread = True
            return 0
        if self.TEXT <= address <= self.TEXT + 0x9c:
            assert self.other_cpu_stalled or (self.preread and (self.ps & 15) >= 5), 'unprotected DPORT read'
            self.preread = False
            if address == self.TEXT + 0x9c:
                assert not self.command_needs_barrier, 'BUSY read before command MEMW barrier'
                if self.busy:
                    self.busy -= 1
                    return 1
                return 0
            assert not self.busy, 'digest read before idle'
            assert self.memory_locked, 'digest read without shared-memory lock'
            self.digest_reads += 1
            return self.text[(address - self.TEXT) // 4]
        if address in self.memory:
            if address == self.generation:
                # Its only writer runs on the other CPU: a read is meaningful only
                # once that CPU is stalled for the group it guards.
                assert self.memory_locked and self.other_cpu_stalled, 'generation read outside the stall'
            if address == self.generation and self.cancel_after is not None and len(self.completed) > self.cancel_after:
                return 20
            return self.memory[address]
        for base, offset, size in self.sections:
            if base <= address < base + size:
                return struct.unpack_from('<I', self.image, offset + address - base)[0]
        raise AssertionError(f'uninitialized read {address:x}')

    def write(self, address, value):
        value &= 0xffffffff
        if self.TEXT <= address < self.TEXT + 64:
            assert self.memory_locked, 'SHA_TEXT access without shared-memory lock'
            assert not self.busy, 'SHA_TEXT written while BUSY'
            self.text[(address - self.TEXT) // 4] = value
            self.writes += 1
        elif address in (self.TEXT + 0x90, self.TEXT + 0x94, self.TEXT + 0x98):
            assert not self.busy and value == 1, 'invalid engine command'
            self.controls.append(address - self.TEXT)
            block = struct.pack('>16I', *self.text)
            if address == self.TEXT + 0x90 and self.phase in (0, 5):
                self.first = block
                self.phase = 1
            elif address == self.TEXT + 0x94 and self.phase == 1:
                assert block[16:] == b'\x80' + bytes(39) + (640).to_bytes(8, 'big')
                self.header = self.first + block[:16]
                self.digest = hashlib.sha256(self.header).digest()
                self.phase = 2
            elif address == self.TEXT + 0x98 and self.phase in (2, 4):
                self.text[:8] = struct.unpack('>8I', self.digest)
                if self.load_clobbers:
                    # A hypothetical chip whose LOAD also disturbs words 9..14 (the
                    # measured engines leave 8..15 alone; nothing documents it).
                    self.text[9:15] = [0xdeadbeef] * 6
                if self.phase == 4: self.completed.append((self.header, self.digest))
                self.phase += 1
            elif address == self.TEXT + 0x90 and self.phase == 3:
                assert block[32:] == b'\x80' + bytes(23) + (256).to_bytes(8, 'big')
                assert block[:32] == self.digest
                self.digest = hashlib.sha256(block[:32]).digest()
                self.phase = 4
            else:
                raise AssertionError('wrong SHA operation order')
            self.busy = self.delay
            self.command_needs_barrier = True
        else:
            self.memory[address] = value

    def read_byte(self, address):
        return (self.read(address & ~3) >> (8 * (address & 3))) & 255

    def write_byte(self, address, value):
        base, shift = address & ~3, 8 * (address & 3)
        old = self.memory.get(base, 0)
        self.memory[base] = (old & ~(255 << shift)) | ((value & 255) << shift)

    def run(self, header, delay=2, initial_level=0, nonces=1, cancel_after=None, tls=0,
            share_difficulty=0.0, network_meets=False, full_padding=0, cpi=None, load_clobbers=False):
        self.memory = {self.generation: 19}
        # TLS CPU-window state (ShaResourcePolicy.h): tls=1 record I/O, tls=2 handshake.
        self.memory[self.statics['secureTransportCpuSessions()::sessions']] = int(tls > 0)
        self.memory[self.statics['secureTransportHandshakeSessions()::sessions']] = int(tls > 1)
        self.memory[self.statics['shaCpuWindowMicroseconds()::value']] = 0
        self.memory[self.statics['shaHandshakeWindowMicroseconds()::value']] = 0
        self.memory[self.statics['s_classic_full_padding']] = full_padding
        self.extra_us = 0
        self.load_clobbers = load_clobbers
        self.cpi = cpi or self.CYCLES_PER_INSTRUCTION
        self.window_request_us = 0
        self.timer_log = []
        self.windows = 0
        self.text = [0] * 16
        self.busy = self.phase = self.writes = self.digest_reads = 0
        self.memory_locked = False
        self.other_cpu_stalled = False
        self.command_needs_barrier = False
        self.delay = delay
        self.preread = False
        self.ps = 0x40000 | initial_level
        initial_ps = self.ps
        self.controls = []
        self.groups = []
        self.completed = []
        self.cancel_after = cancel_after
        self.registers = [0] * 16
        r = self.registers
        r[1:6] = [0x20010000, 0x20000000, 0x20001000, 0x20002000, 0x20003000]
        self.memory[r[2]] = 19
        self.memory[r[2] + 4] = int.from_bytes(header[76:80], 'little')
        self.memory[r[2] + 8] = nonces
        # Job-owned share threshold. 0.0 makes every filter hit a candidate; above
        # the modelled hit difficulty (1.0) no hit is, so the range must continue.
        self.memory[r[2] + 16], self.memory[r[2] + 20] = struct.unpack('<II', struct.pack('<d', share_difficulty))
        for i in range(8):  # network target: nothing meets it, or everything does
            self.memory[r[2] + 332 + 4*i] = 0xffffffff if network_meets else 0
        self.memory[r[3] + 16] = self.memory[r[3] + 20] = 0
        self.memory[r[3] + 136] = 0
        for i in range(20):
            self.memory[r[4] + 4*i] = int.from_bytes(header[4*i:4*i+4], 'big')
            self.memory[r[2] + 252 + 4*i] = int.from_bytes(header[4*i:4*i+4], 'little')
        pc, instructions = self.start, 0
        call_stack = []
        def reg(arg):
            return r[int(arg[1:])]
        def branch(arg):
            return int(arg.split()[0], 16)
        while True:
            op, a, length = self.code[pc]
            pc += length
            instructions += 1
            assert instructions < 10000 * nonces, 'kernel failed to terminate'
            value = None
            if op == 'entry': r[1] -= int(a[1], 0)
            elif op == 'retw':
                if not call_stack:
                    break
                returned = r[2:4]
                pc, parent = call_stack.pop()
                r[:] = parent
                r[10:12] = returned
            elif op == 'memw': self.command_needs_barrier = False
            elif op in ('rsync', 'nop'): pass
            elif op == 'l32r': value = self.read(branch(a[1]))
            elif op == 'l32i': value = self.read(reg(a[1]) + int(a[2], 0))
            elif op == 's32i': self.write(reg(a[1]) + int(a[2], 0), reg(a[0]))
            elif op == 'l8ui': value = self.read_byte(reg(a[1]) + int(a[2], 0))
            elif op == 's8i': self.write_byte(reg(a[1]) + int(a[2], 0), reg(a[0]))
            elif op == 'movi': value = int(a[1], 0)
            elif op == 'mov': value = reg(a[1])
            elif op == 'addi': value = reg(a[1]) + int(a[2], 0)
            elif op == 'add': value = reg(a[1]) + reg(a[2])
            elif op == 'sub': value = reg(a[1]) - reg(a[2])
            elif op == 'minu': value = min(reg(a[1]), reg(a[2]))
            elif op == 'maxu': value = max(reg(a[1]), reg(a[2]))
            elif op == 'addmi': value = reg(a[1]) + int(a[2], 0)
            elif op == 'movnez':
                if reg(a[2]): value = reg(a[1])
            elif op == 'moveqz':
                if not reg(a[2]): value = reg(a[1])
            elif op == 'wsr.scompare1': self.scompare1 = reg(a[0])
            elif op == 's32c1i':
                address = reg(a[1]) + int(a[2], 0)
                old = self.read(address)
                if old == self.scompare1: self.write(address, reg(a[0]))
                value = old
            elif op == 'and': value = reg(a[1]) & reg(a[2])
            elif op == 'or': value = reg(a[1]) | reg(a[2])
            elif op == 'srli': value = reg(a[1]) >> int(a[2], 0)
            elif op == 'slli': value = reg(a[1]) << int(a[2], 0)
            elif op == 'extui': value = (reg(a[1]) >> int(a[2], 0)) & ((1 << int(a[3], 0)) - 1)
            elif op == 'rsil': value, self.ps = self.ps, (self.ps & ~15) | int(a[1], 0)
            elif op == 'wsr.ps': self.ps = reg(a[0])
            elif op == 'bnez':
                if reg(a[0]): pc = branch(a[1])
            elif op == 'beqz':
                if not reg(a[0]): pc = branch(a[1])
            elif op == 'blti':
                signed = reg(a[0]) if reg(a[0]) < 0x80000000 else reg(a[0]) - 0x100000000
                if signed < int(a[1], 0): pc = branch(a[2])
            elif op == 'bgei':
                signed = reg(a[0]) if reg(a[0]) < 0x80000000 else reg(a[0]) - 0x100000000
                if signed >= int(a[1], 0): pc = branch(a[2])
            elif op in ('beqi', 'bnei', 'bltui', 'bgeui'):
                imm = int(a[1], 0) & 0xffffffff
                take = {'beqi': reg(a[0]) == imm, 'bnei': reg(a[0]) != imm,
                        'bltui': reg(a[0]) < imm, 'bgeui': reg(a[0]) >= imm}[op]
                if take: pc = branch(a[2])
            elif op in ('bltu', 'bgeu', 'bne', 'beq'):
                if op == 'bltu': take = reg(a[0]) < reg(a[1])
                elif op == 'bgeu': take = reg(a[0]) >= reg(a[1])
                elif op == 'bne': take = reg(a[0]) != reg(a[1])
                else: take = reg(a[0]) == reg(a[1])
                if take: pc = branch(a[2])
            elif op == 'j': pc = branch(a[0])
            elif op in ('call8', 'callx8'):
                target = branch(a[0]) if op == 'call8' else reg(a[0])
                name = self.names[target]
                if name.startswith('(anonymous namespace)::recordHardwareCandidate('):
                    parent = r.copy()
                    call_stack.append((pc, parent))
                    r[:] = [0, parent[1]] + parent[10:16] + [0] * 8
                    pc = target
                elif name == '__bswapsi2':
                    r[10] = int.from_bytes(r[10].to_bytes(4, 'little'), 'big')
                elif name == 'esp_dport_access_sequence_reg_read':
                    self.preread = True
                    r[10] = self.read(r[10])
                elif name == 'esp_dport_access_reg_read':
                    # SDK routine: RSIL 5, APB pre-read, DPORT load, restore PS.
                    saved_ps = self.ps
                    self.ps = (self.ps & ~15) | 5
                    self.preread = True
                    r[10] = self.read(r[10])
                    self.ps = saved_ps
                elif name == '_xtos_set_intlevel':
                    self.ps = (self.ps & ~15) | (r[10] & 15)
                elif name.startswith('diff_from_target('):
                    actual = b''.join(self.memory[0x20003000 + 4*i].to_bytes(4, 'little') for i in range(8))
                    assert actual == self.digest, 'wrong emitted full digest / endian conversion'
                    assert self.digest[-2:] == b'\0\0', 'false candidate acceptance'
                    # Exercise storage/ownership, not floating-point difficulty
                    # arithmetic (the native suite validates the target gate).
                    r[10], r[11] = 0, 0x3ff00000  # 1.0 > initial 0.0
                elif name in ('__gtdf2', '__gedf2', '__ledf2', '__ltdf2'):
                    left = struct.unpack('<d', struct.pack('<II', r[10], r[11]))[0]
                    right = struct.unpack('<d', struct.pack('<II', r[12], r[13]))[0]
                    r[10] = ((left > right) - (left < right)) & 0xffffffff
                elif name == 'esp_sha_lock_memory_block':
                    assert not self.memory_locked
                    self.memory_locked, self.memory_ps = True, self.ps
                    self.group_began_us = self.timer_log[-1]
                    self.group_began = len(self.completed)
                    self.ps = (self.ps & ~15) | 3
                elif name == 'esp_sha_unlock_memory_block':
                    assert self.memory_locked and not self.busy and not self.other_cpu_stalled
                    self.memory_locked, self.ps = False, self.memory_ps
                    self.groups.append(len(self.completed) - self.group_began)
                elif name == 'esp_ipc_isr_stall_other_cpu':
                    assert self.memory_locked and not self.other_cpu_stalled
                    self.other_cpu_stalled = True
                elif name == 'esp_ipc_isr_release_other_cpu':
                    assert self.memory_locked and self.other_cpu_stalled and not self.busy
                    self.other_cpu_stalled = False
                elif name in ('esp_timer_get_time', 'esp_timer_impl_get_time'):
                    now = 1_000_000 + self.extra_us + instructions * self.cpi // 240
                    self.timer_log.append(now)
                    r[10], r[11] = now & 0xffffffff, now >> 32
                elif name == 'delayMicroseconds':
                    # A TLS CPU window: only with no lock held and the other CPU running,
                    # half the elapsed group time (from the timer reads the kernel made
                    # at group start and just after unlock), capped at 1.5 ms.
                    assert not self.memory_locked and not self.other_cpu_stalled, 'CPU window while locked'
                    assert self.memory[self.statics['secureTransportCpuSessions()::sessions']], 'window without TLS'
                    wanted = min((self.timer_log[-2] - self.group_began_us) // 2, 1500)
                    assert r[10] == wanted, f'CPU window {r[10]} us, expected {wanted}'
                    self.extra_us += r[10]
                    self.windows += 1
                    self.window_request_us += r[10]
                elif name == 'sha_hal_wait_idle':
                    assert self.memory_locked and not self.busy
                elif name.startswith('isSha256Valid('): r[10] = int(any(self.digest))
                elif name.startswith('mining_validation::hashMeetsTarget('):
                    digest = bytes(self.read_byte(r[10] + i) for i in range(32))
                    target = bytes(self.read_byte(r[11] + i) for i in range(32))
                    r[10] = int(int.from_bytes(digest, 'little') <= int.from_bytes(target, 'little'))
                elif name == 'memcpy':
                    data = [self.read_byte(r[11] + i) for i in range(r[12])]
                    for i, byte in enumerate(data): self.write_byte(r[10] + i, byte)
                else: raise AssertionError(f'unexpected call {name}')
            else: raise AssertionError(f'unsupported instruction {op} {a}')
            if value is not None: r[int(a[0][1:])] = value & 0xffffffff
        # The generation can only change while the other CPU runs, so the kernel
        # checks it before each locked group. A change observed after `cancel_after`
        # completed nonces therefore ends the range at the next group boundary.
        start_nonce = int.from_bytes(header[76:80], 'little')
        expected_count = nonces if cancel_after is None else min(
            nonces, (cancel_after // self.GROUP + 1) * self.GROUP)
        candidates = share_difficulty < 1.0 or network_meets
        for i in range(expected_count if candidates else 0):
            candidate_header = header[:76] + ((int.from_bytes(header[76:80], 'little') + i) & 0xffffffff).to_bytes(4, 'little')
            if hashlib.sha256(hashlib.sha256(candidate_header).digest()).digest()[-2:] == b'\0\0':
                expected_count = i + 1
                break
        assert len(self.completed) == expected_count
        hits = []
        for i, (actual_header, digest) in enumerate(self.completed):
            expected_header = header[:76] + ((start_nonce + i) & 0xffffffff).to_bytes(4, 'little')
            expected = hashlib.sha256(hashlib.sha256(expected_header).digest()).digest()
            assert actual_header == expected_header and digest == expected, 'wrong nonce/header'
            if expected[-2:] == b'\0\0': hits.append(expected_header)
        assert self.controls == [0x90, 0x94, 0x98, 0x90, 0x98] * expected_count
        per_nonce = self.FULL_PADDING_WRITES if full_padding else self.WRITES_PER_NONCE
        assert self.writes == per_nonce * expected_count and self.ps == initial_ps
        # Interrupts stay masked for one locked group: bounded, and full-length
        # except where a filter hit or the range end cuts it short.
        assert all(0 <= g <= self.GROUP for g in self.groups), f'lock held for {max(self.groups)} nonces'
        assert sum(self.groups) == expected_count
        if cancel_after is not None:
            # Full groups, then (if the range was cut short) one empty lock in which
            # the stale generation was seen.
            wanted = [self.GROUP] * (expected_count // self.GROUP) + (
                [expected_count % self.GROUP] if expected_count % self.GROUP else [])
            if expected_count < nonces: wanted.append(0)
            assert self.groups == wanted, f'irregular cancelled groups {self.groups} != {wanted}'
        if cancel_after is None:
            wanted, length = [], 0
            for i in range(expected_count):
                nonce_header = header[:76] + ((start_nonce + i) & 0xffffffff).to_bytes(4, 'little')
                length += 1
                if length == self.GROUP or hashlib.sha256(hashlib.sha256(nonce_header).digest()).digest()[-2:] == b'\0\0':
                    wanted.append(length)
                    length = 0
            if length: wanted.append(length)
            assert self.groups == wanted, f'irregular groups {self.groups[:8]} != {wanted[:8]}'
        assert not self.other_cpu_stalled and not self.memory_locked
        assert not self.memory_locked
        if tls and cancel_after is None:
            # Every completed group, hit or range end releases the lock and lends a
            # window; only a generation cancel may return without one.
            assert self.windows > 0, 'TLS active but no CPU window lent'
        if tls:
            window_total = self.memory[self.statics['shaCpuWindowMicroseconds()::value']]
            assert window_total >= self.window_request_us, 'window time not recorded'
            assert (window_total > 0) == (self.windows > 0), 'window time booked without a window'
            assert self.memory[self.statics['shaHandshakeWindowMicroseconds()::value']] == (window_total if tls > 1 else 0)
        else:
            assert self.windows == 0, 'CPU window without TLS'
        hit = bool(hits)
        assert self.digest_reads == expected_count + 7 * len(hits), 'wrong filter branch'
        assert self.memory[0x20001000 + 8] == expected_count, 'wrong completed-nonce count'
        assert self.read_byte(0x20001000 + 136) == int(hit and candidates), 'wrong candidate presence'
        if hit and candidates:
            saved = bytes(self.read_byte(0x20001000 + 56 + i) for i in range(80))
            assert saved in hits, 'candidate header/nonce ownership mismatch'
            assert self.memory[0x20001000 + 4] == int.from_bytes(saved[76:80], 'little')
        return instructions, hit


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('toolchain', type=Path)
    p.add_argument('--cases', type=int, default=10000)
    args = p.parse_args()
    kernel = Kernel(args.elf, args.toolchain)
    rng = random.Random(0x4e657264)
    headers = []
    vectors = Path(__file__).resolve().parents[1] / 'test/native_mining_validation.cpp'
    for match in re.finditer(r'(?:requireDoubleDigest\(|decodeHex\()\s*((?:"[0-9a-f]+"\s*)+)', vectors.read_text()):
        text = ''.join(re.findall(r'"([0-9a-f]+)"', match[1]))
        if len(text) == 160: headers.append(bytes.fromhex(text))
    for nonce in (0, 1, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff):
        headers.append(bytes(76) + nonce.to_bytes(4, 'little'))
    headers.extend(rng.randbytes(80) for _ in range(args.cases))
    # A genuine early-filter hit with nonce UINT32_MAX checks the old sentinel
    # defect using real SHA-256d, not a forged digest or a modified filter.
    for salt in range(2000000):
        header = salt.to_bytes(4, 'little') + bytes(72) + b'\xff' * 4
        if hashlib.sha256(hashlib.sha256(header).digest()).digest()[-2:] == b'\0\0':
            headers.append(header)
            break
    else: raise AssertionError('failed to construct nonce-boundary filter hit')
    hits = total = 0
    for i, header in enumerate(headers):
        count, hit = kernel.run(header, i % 5, i % 5, tls=i % 3)
        total += count
        hits += hit
    for count, cancel_after, start, tls in ((4096, None, 0xfffff000, 1), (16384, None, 0xfffff000, 1),
                                            (3000, None, 0xfffff123, 1), (4096, None, 0xfffff123, 0),
                                            (4096, -1, 0xfffff000, 1), (4096, 0, 0xfffff000, 1),
                                            (4096, 30, 0xfffff123, 0), (4096, 1023, 0xfffff000, 1),
                                            (4096, 1024, 0xfffff123, 1), (1024, 0, 0xfffff000, 1)):
        header = bytes(76) + start.to_bytes(4, 'little')
        count_instructions, _ = kernel.run(header, 2, 0, count, cancel_after, tls=tls)
        print(f'SIMULATED range: requested={count}, cancel_after={cancel_after}, tls={tls}, completed={len(kernel.completed)}, instructions={count_instructions}')
    # A known real Bitcoin hit inside a range must terminate only its prefix;
    # the next invocation must resume the suffix without losing/counting twice.
    original = headers[0]
    start = (int.from_bytes(original[76:80], 'little') - 1) & 0xffffffff
    done = 0
    while done < 32:
        header = original[:76] + ((start + done) & 0xffffffff).to_bytes(4, 'little')
        _, hit = kernel.run(header, 2, 0, 32 - done)
        if done == 0: assert hit and len(kernel.completed) == 2
        done += len(kernel.completed)
    assert done == 32
    print('SIMULATED candidate prefix/suffix: 32 unique nonces, actual historical hit retained.')
    # Below the share difficulty a filter hit is not a candidate (the common case on a
    # pool): the range must continue with the NEXT nonce — none skipped or repeated —
    # with the hit ending its locked group. Hits placed mid-group, on the last nonce of
    # a group and on the first nonce of a group.
    hit_nonce = int.from_bytes(original[76:80], 'little')
    for before, count in ((1, 32), (1023, 2048), (1024, 2048), (0, 5)):
        header = original[:76] + ((hit_nonce - before) & 0xffffffff).to_bytes(4, 'little')
        _, hit = kernel.run(header, 2, 0, count, tls=before % 2, share_difficulty=2.0)
        assert hit and len(kernel.completed) == count
        print(f'SIMULATED non-candidate hit at offset {before}: {count} nonces completed, groups {kernel.groups[:4]}')
    # A candidate in a later group returns the completed prefix including the hit.
    header = original[:76] + ((hit_nonce - 1500) & 0xffffffff).to_bytes(4, 'little')
    _, hit = kernel.run(header, 2, 0, 2048, tls=1)
    assert hit and len(kernel.completed) == 1501 and kernel.groups == [1024, 477]
    # A hit below the share difficulty that still meets the network target is a
    # block: it must be recorded, not treated as a non-candidate.
    header = original[:76] + ((hit_nonce - 5) & 0xffffffff).to_bytes(4, 'little')
    _, hit = kernel.run(header, 2, 0, 16, share_difficulty=2.0, network_meets=True)
    assert hit and len(kernel.completed) == 6
    print('SIMULATED candidate in group 2 and network-target-only candidate: recorded.')
    # Slow groups (a busy bus) must still lend at most 1.5 ms per group.
    header = bytes(76) + (0xfffff123).to_bytes(4, 'little')
    kernel.run(header, 2, 0, 3000, tls=2, cpi=16)
    assert kernel.window_request_us == 3 * 1500, "window cap not applied"
    print(f'SIMULATED slow groups: windows {kernel.window_request_us} us over {kernel.windows} groups (cap 1500).')
    # The fallback selected when the boot known-answer test fails: full padding.
    for i, header in enumerate(headers[:200]):
        kernel.run(header, i % 5, i % 5, tls=i % 3, full_padding=1)
    header = bytes(76) + (0xfffff123).to_bytes(4, 'little')
    kernel.run(header, 2, 0, 3000, tls=1, full_padding=1)
    print(f'SIMULATED full-padding fallback: {Kernel.FULL_PADDING_WRITES} writes per nonce, 200 headers + 3000-nonce range.')
    # On a chip whose LOAD disturbed words 9..14 the two-store padding must hash
    # wrongly (that is what the boot known-answer test detects), and the full-padding
    # fallback must still be exact.
    for i, header in enumerate(headers[:50]):
        kernel.run(header, i % 5, 0, full_padding=1, load_clobbers=True)
    try:
        kernel.run(headers[0], 2, 0, 4, load_clobbers=True)
    except AssertionError:
        print('SIMULATED LOAD that disturbs words 9..14: two-store padding fails, full padding exact.')
    else:
        raise AssertionError('two-store padding passed on a chip whose LOAD disturbs words 9..14')
    print(f'SIMULATED emitted Xtensa kernel: {len(headers)} headers, {hits} full-digest hits, zero mismatches.')
    print(f'{Kernel.WRITES_PER_NONCE} writes / 3 compressions / 2 LOADs; idle-before-write and APB/interrupt protection passed.')
    print(f'Instructions exercised: {total}; no hardware cycle/throughput claim.')


if __name__ == '__main__':
    main()
