"""Test the four pinned vendor slices and negative cases. No device access."""
import argparse
import importlib.util
from pathlib import Path
import re
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('builder', root.parent/'SwipeDeckDirect/build.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

def section(raw):
    pos = 32
    for _ in range(struct.unpack_from('<I', raw, 16)[0]):
        cmd, size = struct.unpack_from('<II', raw, pos)
        if cmd == 0x19:
            for j in range(struct.unpack_from('<I',raw,pos+64)[0]):
                sec = pos+72+j*80
                name = raw[sec:sec+16].rstrip(b'\0')
                segment = raw[sec+16:sec+32].rstrip(b'\0')
                if name == b'__text' and segment == b'__TEXT':
                    addr, length, offset = struct.unpack_from('<QQI',raw,sec+32)
                    return addr,raw[offset:offset+length]
        pos += size
    raise AssertionError('missing __text')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native',action='store_true')
    args = parser.parse_args()
    header = (root/'VerifierPattern.h').read_text()
    words, masks = [
        [int(x,16) for x in re.findall(r'0x[0-9a-f]+',re.search(
            name+r'\[\] = \{(.*?)\};',header,re.S).group(1))]
        for name in ('SDWords','SDMasks')]
    assert len(words)==len(masks)==21
    def scan(raw):
        found=[]
        for offset in range(0,len(raw)-len(words)*4+1,4):
            if all((struct.unpack_from('<I',raw,offset+4*j)[0]&mask)==(word&mask)
                   for j,(word,mask) in enumerate(zip(words,masks))):
                pac = offset>=4 and struct.unpack_from('<I',raw,offset-4)[0]==0xd503237f
                found.append(offset-4 if pac else offset)
        return found
    source = (root.parent/'SwipeDeckDirect/input.deb').read_bytes()
    assert b.hashlib.sha256(source).hexdigest()==b.SOURCE_SHA
    _,payload=b.archive_read(b.ar_parse(source)['data.tar.lzma'])
    cases=[]
    for path in b.TARGETS:
        for _,sub,_,_,raw in b.slices(payload[path]):
            addr,code=section(raw)
            expected=b.TARGETS[path][sub]-addr
            assert scan(code)==[expected], (path,hex(sub),scan(code))
            cases.append((code,[expected]))
            patched=bytearray(code)
            patched[expected:expected+8]=b.PATCH
            assert scan(patched)==[]
            cases.append((bytes(patched),[]))
            print('PASS',Path(path).name,hex(sub),'unique verifier',hex(addr+expected))
    synthetic=struct.pack('<21I',*words)
    for raw,expected in [(b'',[]),(synthetic[:-1],[]),(synthetic,[0]),
        (synthetic*2,[0,len(synthetic)]),(b'\x00'*16+synthetic,[16]),
        (struct.pack('<I',0xd503237f)+synthetic,[0])]:
        assert scan(raw)==expected
        cases.append((raw,expected))
    if args.native:
        with tempfile.TemporaryDirectory(prefix='sd-pattern-') as temp:
            tmp=Path(temp)
            harness=tmp/'test.cpp'
            harness.write_text('''#include <fstream>
#include <iterator>
#include <vector>
#include <cstdio>
#include "VerifierPattern.h"
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    std::ifstream f(argv[1],std::ios::binary);
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(f)),{});
    size_t entry=0, count=SDFindVerifier(data.data(),data.size(),&entry);
    printf("%zu %zu",count,entry);
}
''')
            exe=tmp/'test'
            subprocess.run(['clang++','-std=c++11','-Wall','-Wextra','-Werror',
                '-I',str(root),str(harness),'-o',str(exe)],check=True)
            for i,(raw,expected) in enumerate(cases):
                case=tmp/f'case{i}'
                case.write_bytes(raw)
                count,entry=map(int,subprocess.check_output([str(exe),str(case)]).split())
                assert count==len(expected)
                if expected: assert entry==expected[-1]
            print('PASS exact C++ matcher:',len(cases),'cases')
    print('PASS four original slices, zero patched matches, relocation/duplicate/truncated checks')

if __name__=='__main__': main()
