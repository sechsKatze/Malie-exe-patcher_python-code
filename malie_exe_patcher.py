#!/usr/bin/env python3
"""
MALIE Engine EXE Patcher v4
EXEC.bin을 EXE에 직접 패치 (Resource Hacker 불필요)
- 갭 내 여유 있으면: 뒤 리소스만 이동
- 갭 초과 시: .rsrc 섹션 확장 + 뒤 섹션 이동
오메르타 침묵, CT, 기타 카린 게임 범용 지원
"""
import struct, sys

def parse_rsrc_leaves(data, rsrc_file_off, dir_rva=0):
    base = rsrc_file_off + dir_rva
    named = struct.unpack_from('<H', data, base+12)[0]
    id_cnt = struct.unpack_from('<H', data, base+14)[0]
    leaves = []
    for i in range(named + id_cnt):
        eoff = base + 16 + i*8
        eid  = struct.unpack_from('<I', data, eoff)[0]
        erva = struct.unpack_from('<I', data, eoff+4)[0]
        is_sub = bool(erva & 0x80000000)
        erva &= 0x7FFFFFFF
        if eid & 0x80000000:
            noff = rsrc_file_off + (eid & 0x7FFFFFFF)
            nlen = struct.unpack_from('<H', data, noff)[0]
            name = data[noff+2:noff+2+nlen*2].decode('utf-16-le','replace')
        else:
            name = str(eid & 0x7FFFFFFF)
        if is_sub:
            for leaf in parse_rsrc_leaves(data, rsrc_file_off, erva):
                leaf['path'] = name + '/' + leaf['path']
                leaves.append(leaf)
        else:
            loff = rsrc_file_off + erva
            rva  = struct.unpack_from('<I', data, loff)[0]
            size = struct.unpack_from('<I', data, loff+4)[0]
            leaves.append({'path': name, 'leaf_off': loff, 'rva': rva, 'size': size})
    return leaves

def parse_sections(data):
    e_lfanew  = struct.unpack_from('<I', data, 0x3C)[0]
    num_sect  = struct.unpack_from('<H', data, e_lfanew+6)[0]
    opt_size  = struct.unpack_from('<H', data, e_lfanew+20)[0]
    sect_base = e_lfanew + 24 + opt_size
    sects = []
    for i in range(num_sect):
        s = sect_base + i*40
        sects.append({
            'hdr':    s,
            'name':   data[s:s+8].rstrip(b'\x00').decode('ascii','replace'),
            'vsize':  struct.unpack_from('<I', data, s+8)[0],
            'vaddr':  struct.unpack_from('<I', data, s+12)[0],
            'rawsz':  struct.unpack_from('<I', data, s+16)[0],
            'rawoff': struct.unpack_from('<I', data, s+20)[0],
        })
    return sects, e_lfanew



def rva_to_raw(sects: list[dict], rva: int) -> int:
    for s in sects:
        va = s["vaddr"]
        span = max(s["vsize"], s["rawsz"])
        if va <= rva < va + span:
            return s["rawoff"] + (rva - va)
    raise ValueError(f"RVA 0x{rva:X} not in any section")


def write_u32(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into('<I', buf, off, val)


def add_exec_section(exe: bytes, sects: list[dict], name: str, payload: bytes) -> tuple[bytes, int]:
    """Add new section (raw_ptr == vaddr) containing payload. Returns (new_exe, new_section_rva)."""
    b = bytearray(exe)
    e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
    pe_off = e_lfanew
    if b[pe_off:pe_off+4] != b"PE\0\0":
        raise ValueError("Not a PE file")
    coff_off = pe_off + 4
    nsects = struct.unpack_from("<H", b, coff_off+2)[0]
    opt_size = struct.unpack_from("<H", b, coff_off+16)[0]
    opt_off = coff_off + 20
    sec_tbl = opt_off + opt_size

    # alignment
    file_align = struct.unpack_from("<I", b, opt_off + 36)[0]
    sect_align = struct.unpack_from("<I", b, opt_off + 32)[0]

    # last section header
    last = sects[-1]
    last_end_va = align_up(last["vaddr"] + max(last["vsize"], last["rawsz"]), sect_align)
    new_va = last_end_va
    new_raw_ptr = new_va  # keep the same style as original (raw_ptr == vaddr)
    new_raw_sz = align_up(len(payload), file_align)
    new_vsz = len(payload)

    # ensure section header space
    new_hdr_off = sec_tbl + nsects*40
    first_rawoff = min(s["rawoff"] for s in sects)
    if new_hdr_off + 40 > first_rawoff:
        raise ValueError("Not enough space for new section header")

    # grow file to new_raw_ptr
    if len(b) < new_raw_ptr:
        b.extend(b"\0" * (new_raw_ptr - len(b)))

    # write payload + pad
    b[new_raw_ptr:new_raw_ptr+len(payload)] = payload
    if len(payload) < new_raw_sz:
        b.extend(b"\0" * (new_raw_sz - len(payload)))

    # write section header
    name_bytes = name.encode("ascii", errors="replace")[:8].ljust(8, b"\0")
    characteristics = 0x40000040  # IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    hdr = struct.pack("<8sIIIIIIHHI", name_bytes, new_vsz, new_va, new_raw_sz, new_raw_ptr, 0, 0, 0, 0, characteristics)
    b[new_hdr_off:new_hdr_off+40] = hdr

    # update NumberOfSections
    struct.pack_into("<H", b, coff_off+2, nsects+1)

    # update SizeOfImage
    size_image_off = opt_off + 56
    new_size_image = align_up(new_va + align_up(new_vsz, sect_align), sect_align)
    struct.pack_into("<I", b, size_image_off, new_size_image)

    return bytes(b), new_va
def align_up(v, align):
    return (v + align - 1) & ~(align - 1)

def recalc_checksum(data_bytes):
    e_lfanew   = struct.unpack_from('<I', data_bytes, 0x3C)[0]
    chksum_off = e_lfanew + 24 + 64
    tmp = bytearray(data_bytes)
    struct.pack_into('<I', tmp, chksum_off, 0)
    chk = 0
    for i in range(0, len(tmp)-1, 2):
        chk += struct.unpack_from('<H', tmp, i)[0]
        if chk > 0xFFFFFFFF:
            chk = (chk & 0xFFFFFFFF) + 1
    return (chk + len(data_bytes)) & 0xFFFFFFFF, chksum_off

def patch_exe(exe_path, bin_path, out_path):
    print(f"[*] EXE: {exe_path}")
    print(f"[*] BIN: {bin_path}")
    print(f"[*] OUT: {out_path}")

    orig_exe = open(exe_path, 'rb').read()
    new_bin  = open(bin_path,  'rb').read()

    sects, e_lfanew = parse_sections(orig_exe)
    file_align = struct.unpack_from('<I', orig_exe, e_lfanew+24+36)[0]
    sect_align = struct.unpack_from('<I', orig_exe, e_lfanew+24+32)[0]

    rsrc_sect = next((s for s in sects if s['name'] == '.rsrc'), None)
    if not rsrc_sect:
        print("[!] .rsrc 섹션 없음"); return False

    rsrc_rawoff = rsrc_sect['rawoff']
    rsrc_rawsz  = rsrc_sect['rawsz']
    rsrc_end    = rsrc_rawoff + rsrc_rawsz
    print(f"[*] .rsrc rawoff=0x{rsrc_rawoff:08X} rawsz=0x{rsrc_rawsz:08X} end=0x{rsrc_end:08X}")

    leaves    = parse_rsrc_leaves(orig_exe, rsrc_rawoff)
    # EXEC leaf 선택 규칙:
    # 1) 데이터에 'EXEC' 시그니처가 포함된 leaf 우선
    # 2) 없으면 가장 큰 leaf
    exec_candidates = []
    for lf in leaves:
        try:
            off = rva_to_raw(sects, lf['rva'])
            blob = orig_exe[off:off + min(lf['size'], 0x2000)]
            if b'EXEC' in blob:
                exec_candidates.append(lf)
        except Exception:
            pass
    if exec_candidates:
        exec_leaf = max(exec_candidates, key=lambda x: x['size'])
    else:
        exec_leaf = max(leaves, key=lambda x: x['size'])
    print(f"[*] EXEC: rva=0x{exec_leaf['rva']:08X} size=0x{exec_leaf['size']:08X}")

    old_size = exec_leaf['size']
    new_size = len(new_bin)
    delta    = new_size - old_size
    bin_rva  = exec_leaf['rva']
    bin_off  = rva_to_raw(sects, bin_rva)

    after_leaves = sorted(
        [l for l in leaves if l['rva'] > bin_rva],
        key=lambda x: x['rva']
    )
    last_used = (after_leaves[-1]['rva'] + after_leaves[-1]['size']) if after_leaves else (bin_rva + old_size)
    real_gap  = rsrc_end - last_used

    print(f"[*] 크기 변화: {old_size:,} → {new_size:,} ({delta:+,} bytes)")
    print(f"[*] 실제 갭: {real_gap:,} bytes")

    # ── 모드 결정 ──
    # ── patch 적용 ──
    exe = bytearray(orig_exe)

    if new_size <= old_size:
        # 기존 영역에 덮어쓰기 (남는 부분은 0으로 패딩)
        exe[bin_off:bin_off+new_size] = new_bin
        if new_size < old_size:
            exe[bin_off+new_size:bin_off+old_size] = b'\0' * (old_size - new_size)

        # size만 갱신 (RVA는 그대로)
        write_u32(exe, exec_leaf['leaf_off']+4, new_size)
        print(f"[*] overwrite OK (old_size={old_size:,} -> new_size={new_size:,})")

    else:
        # 더 커진 경우: 새 섹션 추가 후 leaf를 그쪽으로 리다이렉트
        exe2, new_rva = add_exec_section(bytes(exe), sects, ".exec", new_bin)
        exe = bytearray(exe2)

        write_u32(exe, exec_leaf['leaf_off']+0, new_rva)   # RVA
        write_u32(exe, exec_leaf['leaf_off']+4, new_size)  # Size
        print(f"[*] redirect to new section RVA=0x{new_rva:X} (size={new_size:,})")

# 5. PE 체크섬
    chksum, chksum_off = recalc_checksum(bytes(exe))
    struct.pack_into('<I', exe, chksum_off, chksum)
    print(f"[*] PE 체크섬: 0x{chksum:08X}")

    with open(out_path, 'wb') as f:
        f.write(exe)
    print(f"[✓] 완료: {out_path} ({len(exe):,} bytes)")
    return True

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("사용법: python malie_patcher.py <원본EXE> <새BIN> <출력EXE>")
        sys.exit(1)
    sys.exit(0 if patch_exe(sys.argv[1], sys.argv[2], sys.argv[3]) else 1)
