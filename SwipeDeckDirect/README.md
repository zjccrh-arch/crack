# SwipeDeck direct package

Version unlocked6 patches only the signature verifier in `SwipeDeckPrefs` and
the main dylib, preserving IsActivated and its token/cache initialization.
The original vendor package is hash-pinned. macOS uses `ldid` to sign both
binaries; every arm64 and arm64e code page and gate byte is then verified.

This is a version-specific binary patch, not an update-independent Hook.
`unlocked2` has mislabeled compression; `unlocked3` has broken signature
metadata; `unlocked4` does not patch the prefs binary. Do not use those packages.

Device testing is distinct from cloud packaging success. On October 10, 2026,
the missed prefs gate was patched and signed directly on the device, with a
backup retained at `/var/tmp/swipedeck-prefs-fix-20261010/SwipeDeckPrefs.before`.
On October 10, 2026, the preserved-initialization patch plus placing the seed in
the actual RootHide store changed the panel probe from RED_PANEL_NOT_PRESENTED
to GREEN_PANEL_PRESENTED; the user independently confirmed the panel appeared.
The previous Hook wrote into a different filesystem view. The new postinst
seeds the plugin store only if no activation.dat exists and never embeds a
RootHide UUID. Existing data is not overwritten. No Hook package is required.
Button actions and persistence after SpringBoard restart require separate tests.
Versions unlocked4 and unlocked5 skip token initialization and are not functional
release candidates. A displayed activation label is not proof of functionality.
