#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Only the local ECID/signature verifier, never IsActivated.
// Mask relocation-dependent operands; refuse non-unique matches.
static const uint32_t SDWords[] = {
    0xd103c3ff, 0xa9096ffc, 0xa90a67fa, 0xa90b5ff8,
    0xa90c57f6, 0xa90d4ff4, 0xa90e7bfd, 0x910383fd,
    0xaa0103f3, 0xaa0003f4, 0x90000008, 0xf9400108,
    0xf9400108, 0xf81a83a8, 0xaa0103e0, 0x94000000,
    0xaa1303e0, 0x94000000, 0xf101001f, 0x54000001,
    0x4e080e80
};
static const uint32_t SDMasks[] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0x9f00001f, 0xffc003ff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfc000000,
    0xffffffff, 0xfc000000, 0xffffffff, 0xff00001f,
    0xffffffff
};
static size_t SDFindVerifier(const uint8_t *text, size_t size, size_t *entryOffset) {
    size_t count = 0;
    for (size_t offset = 0; offset <= size && size - offset >= sizeof(SDWords); offset += 4) {
        bool matches = true;
        for (size_t j = 0; j < sizeof(SDWords)/sizeof(SDWords[0]); j++) {
            uint32_t word;
            memcpy(&word, text + offset + 4*j, sizeof(word));
            if ((word & SDMasks[j]) != (SDWords[j] & SDMasks[j])) {
                matches = false;
                break;
            }
        }
        if (!matches) continue;
        size_t entry = offset;
        if (offset >= 4) {
            uint32_t previous;
            memcpy(&previous, text + offset - 4, sizeof(previous));
            if (previous == 0xd503237f) entry -= 4; // PACIBSP
        }
        if (entryOffset) *entryOffset = entry;
        count++;
    }
    return count;
}
