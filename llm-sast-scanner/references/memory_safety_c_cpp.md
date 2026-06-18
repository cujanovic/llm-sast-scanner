---
name: memory_safety_c_cpp
description: C/C++ memory safety detection — buffer overflow, use-after-free, unbounded string functions, integer overflow in allocation, and toolchain hardening gaps
---

# C/C++ Memory Safety

Manual memory management in C/C++ enables stack/heap corruption, out-of-bounds access, and lifetime bugs when bounds, sizes, and ownership are not enforced. Static analysis should grep for banned unbounded APIs, trace size arguments to allocation/copy sinks, and flag missing hardening in build configs.

*The core pattern: untrusted or unvalidated length crosses a copy, allocation, or pointer-lifetime boundary without a provable upper bound or safe owner.*

## What It Is (and Is Not)

**What it IS**
- **Stack buffer overflow**: write past fixed `char buf[N]` via unbounded copy/format/read
- **Heap buffer overflow**: write past `malloc`/`new[]` allocation via wrong `size`/`count`
- **Out-of-bounds read/write**: index `arr[i]` or pointer arithmetic without `i < len` proof
- **Use-after-free (UAF)**: dereference after `free`/`delete`; stale pointer in container/callback
- **Double-free**: second `free`/`delete` on same address; `delete` after ownership transfer
- **Unbounded string functions**: `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `scanf("%s")` without width
- **Integer overflow → undersized allocation**: `malloc(n * sizeof(T))` when `n * sizeof(T)` wraps
- **Off-by-one**: loop `<= n`, `strncpy` without null terminator, fencepost in length checks
- **Uninitialized memory**: read of stack/local/heap before write; missing `{}` on C++ objects
- **NULL pointer dereference**: use return value of `malloc`/`realloc`/`fopen`/`getenv` without NULL check
- **Memory leak on realloc failure**: `buf = realloc(buf, n)` overwrites `buf` when `realloc` returns NULL — original block lost
- **Mismatched allocator/deallocator**: `malloc`+`delete`, `new`+`free`, `new[]`+`delete`, `new`+`delete[]` — undefined behavior, heap corruption
- **Incorrect pointer scaling**: `ptr + i * sizeof(T)` when `ptr` is already `T*` — double-scales offset, OOB access
- **Improper null termination**: `memset`/`read` fills buffer but omits `'\0'` before `strcat`/`strcpy`/`strlen`; tainted binary input without terminator
- **`alloca` in loop / unbounded VLA**: stack frame grows each iteration until stack overflow
- **Incorrect buffer size**: `sizeof(pointer)` instead of `sizeof(array)`; `strncpy(dest, src, sizeof(src))`; API `len` arg larger than actual buffer; `malloc(strlen(s))` without room for `'\0'`
- **Integer underflow / signedness**: unsigned `limit - total > 0` wraps when `total > limit`; signed index compared without cast to unsigned
- **Network byte-order as bound**: `ntohl`/`ntohs` result used as index/length without validation against buffer size
- **Return stack address / dangling local**: return `&local` or store address of stack object in outliving structure
- **TOCTOU on file paths (brief)**: `stat`/`access`/`chmod(path)` then operate on same path — attacker swaps target; see `race_conditions.md`
- **Format-string misuse (brief)**: tainted data as format argument to `printf` family — see `format_string_injection.md`
- **Missing toolchain hardening**: release builds without stack canaries, FORTIFY, RELRO, PIE, or dev sanitizers

**What it is NOT**
- **Logic bugs with safe bounds** — correct `snprintf` with `sizeof(dest)` is not overflow
- **Managed-language buffer issues** — Rust `Vec` bounds checks, Java arrays; out of scope unless FFI boundary
- **Full format-string exploitation analysis** — delegate to `format_string_injection.md`
- **Benign memory leaks alone** — unfreed heap at exit; flag `realloc`-loses-block and ownership-loss patterns that enable later corruption
- **DoS from large allocation** — see `denial_of_service.md` unless integer wrap causes undersized buffer then OOB write

## Recon Indicators

### Banned / high-risk functions (grep)

| Function / pattern | Risk | Safer replacement |
|--------------------|------|-------------------|
| `gets(` | Critical — no bounds | `fgets(buf, sizeof(buf), stdin)` |
| `strcpy(` | High — unbounded copy | `snprintf`, `strcpy_s`, `std::string` |
| `strcat(` | High — unbounded append | `snprintf`, `strcat_s` |
| `sprintf(`, `vsprintf(` | High — unbounded format | `snprintf`, `vsnprintf` |
| `scanf("%s"` | High — no width limit | `scanf("%127s", buf)` or `fgets` + parse |
| `strncpy(` without null term | Medium — non-terminated dest | explicit `dest[n-1]='\0'` or `strncpy_s` |
| `strtok(` | Medium — non-reentrant, mutates | `strtok_r`, `strtok_s` |
| `memcpy(`, `memmove(`, `memset(` | Medium — wrong `count` | `*_s` variants; validate count ≤ dest |
| `strlen(` on unbounded input | Medium — drives bad sizes | `strnlen`, bounded scan |
| `realloc(` without temp | High — leak on failure (loses original block) | assign to temp pointer; free original if NULL |
| `free(` / `delete` then use | High — UAF/double-free | null pointer; smart pointers |
| `alloca(` | Medium — stack exhaustion | fixed stack buffer or heap |
| `read(`, `recv(` without cap | Medium — heap/stack fill | bound by buffer size |
| `strncat(` | High — wrong 3rd arg (`sizeof(dest)`, `strlen(dest)`) | `sizeof(dest) - strlen(dest) - 1` |
| `snprintf(`, `vsnprintf(` | Medium — size arg > buffer cap | third arg is `sizeof(dest)` or tracked capacity |
| `malloc\s*\(\s*strlen\s*\(` | High — no space for `'\0'` | `strlen(s) + 1` or `strdup` |
| `alloca(` in loop | High — stack exhaustion | `malloc`/`free` per iteration or once outside loop |
| `sizeof\s*\(\s*\w+\s*\[\s*\]\s*\)` in fn body | High — sizeof pointer, not buffer | pass explicit `size_t buf_len` param |
| `ntohl(`, `ntohs(`, `ntohll(` as index/len | Medium — unvalidated network size | compare against `buf_size` before use |
| `delete\s+\w+` / `delete\[\]` mismatch | High — UB, heap corruption | pair `new`↔`delete`, `new[]`↔`delete[]` |
| `free\s*\(.*\).*new\s|delete\s*\(.*malloc` | Critical — mixed allocators | never mix C heap and C++ new/delete |
| `chmod(`, `stat(`, `access(` on path after open | Medium — TOCTOU | `fchmod`/`fstat` on fd; see `race_conditions.md` |
| `->c_str()` / `&local` returned/stored | High — dangling pointer | extend owner lifetime; heap copy |
| `VLA` / `char buf[n]` with runtime `n` | Medium — stack overflow | cap `n`; use heap for large/unbounded |

Grep anchors: `\b(gets|strcpy|strcat|sprintf|vsprintf|gets|strtok)\s*\(`, `scanf\s*\(\s*["'][^"']*%s`, `strncat\s*\([^)]*,\s*(sizeof|strlen)\s*\(`, `memcpy\s*\([^,]+,[^,]+,\s*[^)]+\)`, `malloc\s*\(\s*strlen\s*\(`, `malloc\s*\([^)]*\*`, `realloc\s*\(\s*\w+\s*,`, `free\s*\([^)]+\)[^;]*;[^}]*\1`, `delete\s+`, `delete\s*\[\s*\]`, `new\s*\[\s*\]`, `alloca\s*\(`, `sizeof\s*\(\s*\w+\s*\)`, `ntohl\s*\(`, `use.?after.?free` (comments/tests).

### Risky structural patterns

```c
// VULN — stack overflow
char buf[64];
strcpy(buf, user_input);

// VULN — heap overflow (count from attacker)
memcpy(heap, src, user_len);

// VULN — integer overflow in size
size_t n = user_count;
char *p = malloc(n * sizeof(item_t));  // wrap → tiny alloc

// VULN — off-by-one
for (int i = 0; i <= n; i++) arr[i] = 0;

// VULN — UAF
free(p);
log("%s", p);

// VULN — double-free
free(p);
free(p);

// VULN — uninitialized read
char tmp[256];
send(sock, tmp, sizeof(tmp), 0);

// VULN — NULL deref after failed alloc
char *p = malloc(n);
strcpy(p, src);

// VULN — realloc loses block on failure
buf = realloc(buf, new_size);

// VULN — sizeof pointer, not buffer
void copy(char s[]) { memcpy(d, s, sizeof(s)); }

// VULN — improper null termination before strcat
memset(dest, 'A', 99);
strcat(dest, src);

// VULN — alloca in loop
for (int i = 0; i < n; i++) { char *p = alloca(len); }

// VULN — unsigned underflow in bound check
while (limit - total > 0) { total += chunk; }

// VULN — network index unchecked
int i = ntohl(net_len);
return buf[i];
```

```cpp
// VULN — raw owning pointer
int *p = new int[n];
delete[] p;
process(p);

// VULN — vector index without check
items[user_idx] = x;

// VULN — dangling reference
std::string_view sv = local_string();
return sv.data();

// VULN — temporary c_str() UAF
const char *p = (s1 + s2).c_str();
c_api(p);

// VULN — new[]/delete mismatch
int *a = new int[10];
delete a;

// VULN — return stack address
Record *mk() { Record r; return &r; }
```

### Build / CI config (grep)

| Signal | Flag when absent in release or debug |
|--------|--------------------------------------|
| Stack canary | no `-fstack-protector-strong` / `-fstack-protector-all` |
| FORTIFY | no `-D_FORTIFY_SOURCE=2` with `-O1+` |
| PIE/ASLR | no `-fPIE` + linker `-pie` |
| RELRO | no `-Wl,-z,relro,-z,now` |
| NX stack | no `-Wl,-z,noexecstack` |
| Warnings | no `-Wall -Wextra -Wformat -Wformat-security` |
| Sanitizers (dev) | no `-fsanitize=address,undefined` on CI/debug builds |
| `_FORTIFY_SOURCE=0` | explicitly disables fortification |

Search: `CMakeLists.txt`, `Makefile`, `*.mk`, `meson.build`, `BUILD`, `.bazelrc`, `compile_commands.json`, compiler flag variables (`CFLAGS`, `CXXFLAGS`, `LDFLAGS`).

## Vulnerable vs Secure Examples

### Stack / heap buffer overflow

```c
// VULN
char dest[32];
strcpy(dest, src);

// SECURE
if (snprintf(dest, sizeof(dest), "%s", src) >= (int)sizeof(dest))
    return ERROR;
```

```c
// VULN
char *buf = malloc(len);
memcpy(buf, data, len + 1);  // len+1 exceeds allocation

// SECURE
if (len >= cap) return ERROR;
memcpy(buf, data, len);
```

### Out-of-bounds access

```c
// VULN
buf[idx] = c;  // idx unchecked

// SECURE
if (idx >= buf_size) return ERROR;
buf[idx] = c;
```

```cpp
// VULN
return vec.at(user_index);  // if .at missing and operator[] used without check

// SECURE
if (user_index >= vec.size()) throw std::out_of_range("index");
return vec[user_index];
```

### Use-after-free / double-free

```c
// VULN
free(node);
traverse(list);  // list still references node

// SECURE
free(node);
node = NULL;
list_remove(&list, node);
```

```cpp
// VULN
std::unique_ptr<Foo> a = std::make_unique<Foo>();
Foo *raw = a.get();
a.reset();
raw->bar();

// SECURE — no raw use after release
{
    auto a = std::make_unique<Foo>();
    a->bar();
}
```

#### Interprocedural UAF (free and use in different functions)

Many real UAFs span function boundaries — the pointer is freed in one function and dereferenced in another reachable through the call graph (or via a shared global/struct field). Trace these, not just same-function cases.

- **Free operations (incl. custom wrappers)**: `free(`, `delete`/`operator delete`, kernel allocators `kfree(`/`kvfree(`, and **any project-specific wrapper** — treat a function whose name contains `free`/`release`/`destroy`/`put`/`cleanup` as a deallocator when it frees its argument. Flag the freed pointer (and aliases/copies) as tainted.
- **Dangerous sinks for the freed pointer**: dereference (`*p`), array index (`p[i]`), member access (`p->field`), or passing it as an argument to another function that dereferences it.
- **Propagation to follow**: copies/aliases (`q = p;`), struct field stores (`ctx->buf = p;`) and later `ctx->buf` reads, pass-through via function parameters and return values, and the same global/field touched by two functions sharing a caller.
- **Barriers that clear the finding** (must occur on the path between free and use): reassignment to `NULL`/`0`, or **reallocation** of the same pointer (`malloc`/`calloc`/`realloc`/`new`, kernel `kmalloc`/`kzalloc`/`kvmalloc`).
- **Triage before reporting**: (1) does the free provably execute *before* the use on some path? (2) is it the *same* object/alias (pointer-type-compatible)? (3) is the object still freed at the use (not nulled, reinitialized, or reallocated)? A double-free is the same pattern with a second deallocator as the sink.

### Unbounded input (`gets`, `scanf`)

```c
// VULN
gets(line);

// SECURE
if (!fgets(line, sizeof(line), stdin)) return ERROR;
line[strcspn(line, "\n")] = '\0';
```

```c
// VULN
scanf("%s", name);

// SECURE
if (scanf("%31s", name) != 1) return ERROR;
```

### Integer overflow → undersized allocation

```c
// VULN
size_t total = count * elem_size;
void *p = malloc(total);

// SECURE
if (count != 0 && elem_size > SIZE_MAX / count) return ERROR;
size_t total = count * elem_size;
void *p = malloc(total);
```

### Off-by-one / `strncpy` pitfall

```c
// VULN — no null terminator when src len >= sizeof(dest)
strncpy(dest, src, sizeof(dest));

// SECURE
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';
```

### Uninitialized memory

```c
// VULN
struct pkt hdr;
write(fd, &hdr, sizeof(hdr));

// SECURE
struct pkt hdr = {0};
/* or memset(&hdr, 0, sizeof(hdr)); */
write(fd, &hdr, sizeof(hdr));
```

```cpp
// VULN
int x;
if (x > 0) use(x);

// SECURE
int x = 0;
if (x > 0) use(x);
```

### Format string (cross-reference)

```c
// VULN — see format_string_injection.md
printf(user_msg);

// SECURE
printf("%s", user_msg);
```

### NULL pointer dereference

```c
// VULN
char *p = getenv("HOME");
strcpy(buf, p);

// SECURE
char *p = getenv("HOME");
if (p == NULL) return ERROR;
if (snprintf(buf, sizeof(buf), "%s", p) >= (int)sizeof(buf)) return ERROR;
```

### Memory leak on failed `realloc`

```c
// VULN — original block lost if realloc fails
buf = realloc(buf, new_size);

// SECURE
void *tmp = realloc(buf, new_size);
if (tmp == NULL) { free(buf); return ERROR; }
buf = tmp;
```

### Mismatched allocator / deallocator

```cpp
// VULN
int *p = (int *)malloc(n * sizeof(int));
delete p;

// SECURE
int *p = (int *)malloc(n * sizeof(int));
free(p);
```

```cpp
// VULN
int *a = new int[n];
delete a;  // should be delete[]

// SECURE
int *a = new int[n];
delete[] a;
```

### Incorrect pointer scaling

```c
// VULN — offset scaled twice
return *(intPointer + (i * sizeof(int)));

// SECURE
return intPointer[i];
```

### Improper null termination (non-`strncpy` paths)

```c
// VULN — dest not terminated before strcat
memset(dest, 'B', 99);
strcat(dest, source);

// SECURE
memset(dest, 'B', 99);
dest[99] = '\0';
strcat(dest, source);
```

```c
// VULN — read() bytes not terminated before string use
ssize_t n = read(fd, buf, sizeof(buf));
strcpy(copy, buf);

// SECURE
ssize_t n = read(fd, buf, sizeof(buf) - 1);
if (n <= 0) return ERROR;
buf[n] = '\0';
strcpy(copy, buf);
```

### `alloca` in loop

```c
// VULN
for (int i = 0; i < count; i++) {
    char *path = alloca(path_len);
    use(path);
}

// SECURE
for (int i = 0; i < count; i++) {
    char *path = malloc(path_len);
    if (!path) return ERROR;
    use(path);
    free(path);
}
```

### Incorrect buffer size calculation

```c
// VULN — sizeof decays to pointer size
void f(char s[]) {
    memcpy(d, s, sizeof(s));
}

// SECURE
void f(const char *s, size_t s_len, char *d, size_t d_cap) {
    if (s_len > d_cap) return ERROR;
    memcpy(d, s, s_len);
}
```

```c
// VULN — no room for terminator
copy = malloc(strlen(input));
strcpy(copy, input);

// SECURE
copy = malloc(strlen(input) + 1);
if (!copy) return NULL;
strcpy(copy, input);
```

```c
// VULN — flipped strncpy size (source size used)
strncpy(dest, src, sizeof(src));

// SECURE
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';
```

```c
// VULN — strncat off-by-one (no space for appended '\0')
strncat(dest, src, sizeof(dest) - strlen(dest));

// SECURE
strncat(dest, src, sizeof(dest) - strlen(dest) - 1);
```

### Integer underflow in bounds check

```c
// VULN — unsigned wrap when total > limit
while (limit - total > 0) { total += get_data(); }

// SECURE
while (total < limit) { total += get_data(); }
```

### Network byte-order index without validation

```c
// VULN
int i = ntohl(get_net_u32());
return buff[i];

// SECURE
uint32_t i = ntohl(get_net_u32());
if (i >= buff_size) return ERROR;
return buff[i];
```

### Return stack address / dangling local

```c
// VULN
Record *mk(int v) {
    Record r(v);
    return &r;
}

// SECURE
Record *mk(int v) {
    Record *r = malloc(sizeof(Record));
    if (!r) return NULL;
    *r = (Record){ .value = v };
    return r;
}
```

### TOCTOU on file path (cross-reference)

```c
// VULN — path may change between open and chmod
f = fopen(path, "w");
chmod(path, S_IRUSR);

// SECURE — operate on same inode via fd
fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
fchmod(fd, S_IRUSR);
```

See `race_conditions.md` for symlink races and check-then-use patterns.

### C++ temporary lifetime / iterator invalidation (UAF depth)

```cpp
// VULN — temporary destroyed before c_api returns
void bad(std::string a, std::string b) {
    c_api((a + b).c_str());
}

// SECURE
void good(std::string a, std::string b) {
    std::string combined = a + b;
    c_api(combined.c_str());
}
```

```cpp
// VULN — erase invalidates iterator
for (auto it = v.begin(); it != v.end(); ++it)
    if (*it % 2 == 0) v.erase(it);

// SECURE
for (auto it = v.begin(); it != v.end(); )
    if (*it % 2 == 0) it = v.erase(it); else ++it;
```

### Double-free via exception path

```cpp
// VULN — catch may delete already-freed pointer
try { delete task; ... } catch (...) { delete task; }

// SECURE
try { delete task; task = nullptr; ... } catch (...) { delete task; }
```

## Safe Patterns

**Bounded C APIs**
- Copy/format: `snprintf(dest, sizeof(dest), ...)`, `strncpy_s`, `strcpy_s`, `strcat_s`
- Input: `fgets(buf, sizeof(buf), stream)`; `scanf` with width (`"%Ns"`)
- Memory: `memcpy_s(dest, dest_size, src, count)`; verify `count <= dest_size`
- Length: `strnlen_s(s, max)` before copy; never `sizeof(pointer)` for buffer size — pass `buf_size` param
- `realloc`: always assign to temp; `free(original)` on failure before returning
- Pair allocators: `malloc`/`calloc`/`realloc` ↔ `free`; `new` ↔ `delete`; `new[]` ↔ `delete[]`; never cross C/C++ heaps
- Pointer bounds: compare index to length as unsigned (`(size_t)i < len`); avoid `ptr + i < ptr_end` overflow checks — compare `i` to `len` first
- Network sizes: validate `ntohl`/`ntohs` result against local buffer capacity before indexing
- File paths: prefer fd-based APIs (`fchmod`, `fstat`) over path-based after open — see `race_conditions.md`

**C++ containers and RAII**
- Prefer `std::string`, `std::vector`, `std::array` over raw buffers
- Ownership: `std::unique_ptr`, `std::shared_ptr`; avoid `new`/`delete` in application code
- Bounds: `.at(i)` or explicit `if (i < v.size())`; range-for over indices
- Initialization: value-initialize (`T x{}`, `{0}`), member init lists, `std::fill`

```cpp
// SAFE — vector + bounded copy
std::vector<char> buf(max_len);
std::copy_n(src.begin(), std::min(src.size(), buf.size()), buf.begin());
```

```c
// SAFE — Annex K style with error check
if (strcpy_s(dest, sizeof(dest), src) != 0)
    return EINVAL;
```

**Lifetime**
- Single owner; transfer with move/`release()` explicitly
- Set pointer to `NULL` after `free` if legacy API requires manual free; same for `delete` in exception handlers
- Do not store raw pointers to stack/local objects in long-lived structures
- After `read`/`recv`/`fread`: write explicit `'\0'` before C string APIs if data may be binary

**Static analysis / review checklist**
- Every `memcpy`/`memmove`/`read`/`recv`: prove `count <= destination_capacity`
- Every loop index: prove `0 <= i < length` (strict `<`, not `<=`, unless fencepost intentional)
- Every `malloc(n * m)`: overflow guard before multiply
- Every `malloc(strlen(s))`: add `+ 1` for terminator
- Every `strncpy`/`strncat`: third arg from **destination** remaining space, minus 1 for `'\0'`
- Every `memset` on struct/array: third arg is byte size (`sizeof(type)` or `sizeof(array)`, not `sizeof(ptr)`)
- Every banned function: replace or document platform-safe wrapper with tests

## Toolchain Hardening

Defense-in-depth does not fix bugs but raises exploit cost and catches errors in CI.

| Control | Compiler / linker flags | Detects / mitigates |
|---------|-------------------------|---------------------|
| Stack canary | `-fstack-protector-strong` or `-fstack-protector-all` | Stack smashes before return |
| FORTIFY_SOURCE | `-D_FORTIFY_SOURCE=2` with `-O1`+ | Runtime checks on libc string/mem calls |
| PIE + ASLR | `-fPIE` (compile), `-pie` (link) | Randomized load addresses |
| RELRO | `-Wl,-z,relro,-z,now` | GOT overwrite harder |
| NX stack | `-Wl,-z,noexecstack` | Non-executable stack |
| Warnings | `-Wall -Wextra -Wconversion -Wformat -Wformat-security` | Latent bugs at compile time |
| ASan | `-fsanitize=address` (debug/CI) | Heap/stack OOB, UAF, leaks |
| UBSan | `-fsanitize=undefined` | UB including overflow, misaligned access |

**Debug vs release**
- Debug/CI: `-O0 -g`, `-fsanitize=address,undefined` (avoid combining ASan with MSan in same build)
- Release: `-O2`, hardening flags above, `-DNDEBUG`; never ship sanitizers

```cmake
# Release hardening sketch
target_compile_options(app PRIVATE -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2)
target_link_options(app PRIVATE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack)
```

Verify binaries in CI (e.g., `checksec --file=./app`) for RELRO, PIE, NX, canary.

## Common False Alarms

- **`memcpy` with constant sizes** on fixed stack arrays when `count` is compile-time provable ≤ `sizeof(dest)`
- **`strncpy` in legacy code** with immediate null termination on the last byte — safe if pattern is complete
- **`scanf("%127s", buf)`** with width strictly less than buffer size — bounded; still prefer `fgets` for line input
- **Smart pointer `.get()`** used only before owner destruction in same scope — not UAF
- **`strlen` on trusted literals** or static config — not unbounded external input
- **FORTIFY / stack protector in binary** — mitigations present; downgrade exploit likelihood, do not withdraw source-level finding
- **Test/fixture code** using banned functions in isolated fuzz harnesses — note context; flag if compiled into production target
- **C++ `std::vector::operator[]`** after explicit size check or when index is loop variable bounded by `.size()`
- **Integer multiply** with small compile-time constants where overflow is impossible by inspection
- **Annex K `*_s` functions** unavailable on target platform — suggest `snprintf`/bounds pattern instead of false CONFIRMED on missing API
- **`if (ptr) free(ptr)` without subsequent NULL assign** — idempotent free is safe only once; flag only when second free path exists on same pointer
- **`ntohl` on constant or pre-validated header field** — downgrade if upstream parser already bounds-checked packet length
- **`alloca` once outside loop** with compile-time-bounded size — not loop-stack-exhaustion pattern
- **Guarded `delete` in catch after `delete; ptr=nullptr` in try** — second delete is harmless on NULL
