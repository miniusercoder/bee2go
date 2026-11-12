# Architecture

The module is github.com/miniusercoder/bee2go/v3. Public packages group algorithms by family. The root defines shared errors. Production CGo and unsafe operations live in internal/native. Native objects own wiped C allocations and support idempotent Close. Public packages never expose native pointers. Objects require caller synchronization; independent objects may run concurrently.

During migration internal/staging contains the old implementation and self-tests. New packages never import staging. It is removed after symmetric, BIGN and BAKE migration.

bee2 is pinned by gitlink. scripts/build_bee2.sh verifies the checkout and builds library and upstream tests in build/configs/<configuration fingerprint>, selected through build/bee2. The fingerprint includes revision, compiler version, CFLAGS, LDFLAGS and build type. Run make test-c to execute the C suite.
