# SwipeDeck direct package

Fixes the missed licensing copy in `SwipeDeckPrefs`, as well as the main dylib.
The original vendor package is hash-pinned. macOS uses `ldid` to sign both
binaries; every arm64 and arm64e code page and gate byte is then verified.

This is a version-specific binary patch, not an update-independent Hook.
`unlocked2` has mislabeled compression; `unlocked3` has broken signature
metadata; `unlocked4` does not patch the prefs binary. Do not use those packages.

Device testing is distinct from cloud packaging success. On October 10, 2026,
the missed prefs gate was patched and signed directly on the device, with a
backup retained at `/var/tmp/swipedeck-prefs-fix-20261010/SwipeDeckPrefs.before`.
Visible UI and functionality still need device confirmation.
