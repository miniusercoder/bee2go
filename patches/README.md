# Patches to the pinned bee2 backend

The gitlink remains `4341f7a5c300f8e6dc292559e671eb899d831433`.
The build script extracts that exact revision into a generated source directory
and applies the tracked patches. Original submodule files stay untouched.
Patch bytes are part of the build fingerprint and generated CGo cache identity.

`bee2-bauth-challenge.patch` corrects the BAuth terminal challenge length.
The header and terminal step specify 16 bytes. The token step previously hashed
24/32 bytes at levels 192/256, reading beyond message M2 and failing key
confirmation. Both M2 precondition lengths also had a conditional-expression
precedence error. The patch changes no wire format and preserves level128.
`btok.TestBAuthAllLevels` reproduces the unpatched authentication failure and
checks all three levels with and without mutual authentication after the fix.

Updating bee2 requires explicitly rebasing or dropping this patch, rerunning the
Go and C suites, and recording the new revision. Patch application uses no fuzz.
