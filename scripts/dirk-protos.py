"""Find the protobuf file descriptors a Go binary embeds and print them as .proto text.

Usage: python3 -I scripts/dirk-protos.py <binary> <outdir> name.proto [name.proto ...]
For Dirk 1.2.1: signer.proto lister.proto endpoint.proto eth2.proto responsestate.proto
"""
import os
import sys


def varint(b, i):
    x = 0
    s = 0
    while True:
        if i >= len(b):
            raise ValueError("eof")
        c = b[i]
        i += 1
        x |= (c & 0x7F) << s
        s += 7
        if not c & 0x80:
            return x, i
        if s > 63:
            raise ValueError("varint")


def fields(b):
    """Parse a whole message; raises on malformed input."""
    i = 0
    out = []
    while i < len(b):
        key, i = varint(b, i)
        num, wt = key >> 3, key & 7
        if num == 0:
            raise ValueError("field 0")
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            n, i = varint(b, i)
            if i + n > len(b):
                raise ValueError("len")
            v = b[i:i + n]
            i += n
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        else:
            raise ValueError("wire type")
        out.append((num, wt, v))
    return out


FILE_FIELDS = {1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2, 9: 2, 10: 0, 11: 0, 12: 2}


def prefix_len(b, start):
    """Length of the longest prefix at start that parses as FileDescriptorProto fields."""
    i = start
    last_ok = start
    while i < len(b):
        try:
            key, j = varint(b, i)
            num, wt = key >> 3, key & 7
            if FILE_FIELDS.get(num) != wt:
                break
            if wt == 0:
                _, j = varint(b, j)
            else:
                n, j = varint(b, j)
                if j + n > len(b):
                    break
                j += n
            i = j
            last_ok = i
        except ValueError:
            break
    return last_ok - start


def s(v):
    return v.decode()


TYPES = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64", 7: "fixed32", 8: "bool",
         9: "string", 12: "bytes", 13: "uint32", 15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}


def tname(f):
    t = f.get(5)
    if t in (11, 14):
        return f[6]
    return TYPES[t]


def field_dict(b):
    d = {}
    for num, wt, v in fields(b):
        d[num] = s(v) if wt == 2 and num in (1, 2, 6, 7, 10) else v
    return d


def emit_message(b, ind, out):
    fs = fields(b)
    name = s([v for n, _, v in fs if n == 1][0])
    out.append(f"{ind}message {name} {{")
    oneofs = [s(fields(v)[0][2]) for n, _, v in fs if n == 8]
    flist = [field_dict(v) for n, _, v in fs if n == 2]
    for n, _, v in fs:
        if n == 3:
            emit_message(v, ind + "  ", out)
        if n == 4:
            emit_enum(v, ind + "  ", out)
    done = set()
    for f in flist:
        oi = f.get(9)
        if oi is not None and not f.get(17):
            if oi in done:
                continue
            done.add(oi)
            out.append(f"{ind}  oneof {oneofs[oi]} {{")
            for g in flist:
                if g.get(9) == oi:
                    out.append(f"{ind}    {tname(g)} {g[1]} = {g[3]};")
            out.append(f"{ind}  }}")
            continue
        label = "repeated " if f.get(4) == 3 else ("optional " if f.get(17) else "")
        out.append(f"{ind}  {label}{tname(f)} {f[1]} = {f[3]};")
    out.append(f"{ind}}}")


def emit_enum(b, ind, out):
    fs = fields(b)
    name = s([v for n, _, v in fs if n == 1][0])
    out.append(f"{ind}enum {name} {{")
    for n, _, v in fs:
        if n == 2:
            d = {k: x for k, _, x in fields(v)}
            out.append(f"{ind}  {s(d[1])} = {d.get(2, 0)};")
    out.append(f"{ind}}}")


def emit_file(b):
    out = []
    fs = fields(b)
    d = {}
    for n, wt, v in fs:
        d.setdefault(n, []).append(v)
    syntax = s(d[12][0]) if 12 in d else "proto2"
    out.append(f'syntax = "{syntax}";')
    out.append("")
    out.append(f"// {s(d[1][0])}, recovered from the descriptor embedded in the Dirk binary.")
    out.append(f"package {s(d[2][0])};")
    out.append("")
    for dep in d.get(3, []):
        out.append(f'import "{s(dep)}";')
    if 8 in d:
        for n, wt, v in fields(d[8][0]):
            if wt == 2:
                out.append(f'// file option {n}: "{s(v)}"')
    out.append("")
    for m in d.get(4, []):
        emit_message(m, "", out)
        out.append("")
    for e in d.get(5, []):
        emit_enum(e, "", out)
        out.append("")
    for sv in d.get(6, []):
        sf = fields(sv)
        out.append(f"service {s([v for n, _, v in sf if n == 1][0])} {{")
        for n, _, v in sf:
            if n == 2:
                md = {k: x for k, _, x in fields(v)}
                cs = "stream " if md.get(5) else ""
                ss = "stream " if md.get(6) else ""
                out.append(f"  rpc {s(md[1])}({cs}{s(md[2])}) returns ({ss}{s(md[3])});")
        out.append("}")
        out.append("")
    return "\n".join(out)


def main():
    data = open(sys.argv[1], "rb").read()
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    for name in sys.argv[3:]:
        nb = name.encode()
        pat = b"\x0a" + bytes([len(nb)]) + nb
        best = None
        i = data.find(pat)
        while i >= 0:
            n = prefix_len(data, i)
            if best is None or n > best[1]:
                best = (i, n)
            i = data.find(pat, i + 1)
        if best is None:
            print(f"{name}: not found")
            continue
        raw = data[best[0]:best[0] + best[1]]
        open(os.path.join(outdir, name + ".desc"), "wb").write(raw)
        text = emit_file(raw)
        open(os.path.join(outdir, name), "w").write(text + "\n")
        print(f"{name}: offset {best[0]}, {best[1]} bytes")


main()
