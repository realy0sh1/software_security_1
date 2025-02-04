// This is a tiny allocator with a few odd design choices (primarily, pointers instead of sizes in the chunk header)
// that are supposed to make it a little bit more interesting to exploit. It really only supports
// malloc/calloc/realloc/reallocarray and free, as well as malloc_usable_size. The APIs to allocate aligned memory
// are not supported. Multithreading is also not supported.

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define heap_assert(check, msg) do { if (!(check)) heap_assert_failed(msg, __func__); } while (0)
static inline __attribute__((always_inline, noreturn)) void heap_assert_failed(const char *msg, const char *func) {
    write(STDERR_FILENO, func, strlen(func));
    write(STDERR_FILENO, "(): ", 4);
    write(STDERR_FILENO, msg, strlen(msg));
    write(STDERR_FILENO, "\n", 1);
    abort();
}

/// Flags for our chunks.
enum malloc_chunk_flags {
    MCF_INUSE = 1 << 0, /// Marks allocated chunks
    MCF_PREVINUSE = 1 << 1, /// Marks that the previous chunk is in use.
    MCF_TOP = 1 << 2, /// Marks the top chunk/wilderness (= the last chunk in the heap)
    MCF_FIRST = 1 << 3, /// Marks the first chunk in the heap
    MCF_FREELIST = 1 << 4, /// Marks the chunk as on the freelist.
};

/// Memory chunks.
struct malloc_chunk {
    /// Overlap with the previous chunk, if not MCF_PREVINUSE
    struct malloc_chunk *prev;

    /// Actual chunk header
    union {
        uint64_t chunk_header; // This is just here so we can verify the offsets properly
        struct __attribute__((packed)) {
            /// Pointers fit into 48 bits on (most) x86-64 systems, and into 57 bits if you happen to have 5-level paging enabled (you probably don't).
            /// In any case, the top 7 bits are always free, which is enough for the flags.
            uintptr_t next : 57; // This can't be a struct malloc_chunk * due to C rules, but it is.
            enum malloc_chunk_flags flags : 7;
        };
    };

    union {
        /// Freelist overlaps with the chunk data, if not MCF_INUSE
        struct {
            struct malloc_chunk *fd;
            struct malloc_chunk *bk;
        };
        /// Chunk data (for MCF_INUSE chunks).
        char user_data[1]; // This doesn't really have a fixed size, but it can't be a flexible array member because those aren't allowed in unions (grrr)
    };
};
static_assert(sizeof(struct malloc_chunk) == 0x20, "bad chunk layout (chunk size)");
static_assert(offsetof(struct malloc_chunk, user_data) == 0x10, "bad chunk layout (header size)");
static_assert(offsetof(struct malloc_chunk, chunk_header) == 0x8, "bad chunk layout (size of overlap with previous chunk)");

#define in_use(chunk) ((chunk)->flags & MCF_INUSE)
#define prev_in_use(chunk) ((chunk)->flags & MCF_PREVINUSE)
#define is_top(chunk) ((chunk)->flags & MCF_TOP)
#define is_first(chunk) ((chunk)->flags & MCF_FIRST)
#define in_freelist(chunk) ((chunk)->flags & MCF_FREELIST)

/// An arena. Really, there is _only_ main_arena in this allocator.
struct arena {
    union {
        /// Actual extents of the heap. This overlaps with the chunk header in such a way that this basically is just
        /// start, end, and the freelist pointers.
        struct {
            void *start;
            void *end;
        };
        /// This pretends to be a chunk so it becomes easier to traverse lists.
        struct malloc_chunk freelist_head;
    };
} main_arena = { 0 };

/// For a chunk, get the previous chunk in memory (if it exists and is not in use).
static inline __attribute__((always_inline)) struct malloc_chunk *previous_chunk(struct malloc_chunk *chunk) {
    heap_assert(!is_first(chunk), "heap corruption (trying to move beyond first chunk)");
    heap_assert(!prev_in_use(chunk), "heap corruption (trying to use overlap with in-use chunk)");
    heap_assert(chunk->prev < chunk, "heap corruption (previous chunk is after current chunk)");
    return chunk->prev;
}

/// For a chunk, get the next chunk in memory, if it exists.
static inline __attribute__((always_inline)) struct malloc_chunk *next_chunk(struct malloc_chunk *chunk) {
    struct malloc_chunk *next = (struct malloc_chunk *) (uintptr_t) chunk->next;
    heap_assert(next > chunk, "heap corruption (next chunk is in front of current chunk)");
    return next;
}

/// For a chunk, get the next chunk on the freelist.
static inline __attribute__((always_inline)) struct malloc_chunk *fd_chunk(struct malloc_chunk *chunk) {
    heap_assert(!in_use(chunk), "heap corruption (trying to use data of in-use chunk as metadata)");
    heap_assert(in_freelist(chunk), "heap corruption (trying to follow freelist via unlisted chunk)");
    return chunk->fd;
}

/// For a chunk, get the previous chunk on the freelist.
static inline __attribute__((always_inline)) struct malloc_chunk *bk_chunk(struct malloc_chunk *chunk) {
    heap_assert(!in_use(chunk), "heap corruption (trying to use data of in-use chunk as metadata)");
    heap_assert(in_freelist(chunk), "heap corruption (trying to follow freelist via unlisted chunk)");
    return chunk->bk;
}

/// Get the size of a chunk.
static inline __attribute__((always_inline)) size_t chunk_size(struct malloc_chunk *chunk) {
    return (char *) next_chunk(chunk) - (char *) chunk;
}

/// Turn the chunk size into the size of the usable user memory inside the chunk.
static inline __attribute__((always_inline)) size_t usable_size(size_t chunk_size) {
    // Subtract anything that doesn't overlap with the user data, but add everything back in that overlaps with the next chunk.
    return chunk_size - offsetof(struct malloc_chunk, user_data) + offsetof(struct malloc_chunk, chunk_header);
}

/// Turn a chunk pointer into a pointer to the user memory.
static inline __attribute__((always_inline)) void *user_data(struct malloc_chunk *chunk) {
    return &chunk->user_data;
}

/// Turn a pointer to user memory into a chunk pointer
static inline __attribute__((always_inline)) struct malloc_chunk *chunk_for(void *user_data) {
    return (struct malloc_chunk *) ((char *) user_data - offsetof(struct malloc_chunk, user_data));
}

/// Add a chunk to the freelist before the specified chunk
static void enqueue_before(struct malloc_chunk *before, struct malloc_chunk *chunk) {
    heap_assert(!in_use(chunk), "heap corruption (trying to enqueue in-use chunk)");
    heap_assert(!in_freelist(chunk), "heap corruption (trying to double-enqueue chunk)");
    before->bk->fd = chunk;
    chunk->bk = before->bk;
    chunk->fd = before;
    before->bk = chunk;
    chunk->flags |= MCF_FREELIST;
}

/// Add a chunk to the freelist after the specified chunk
static void enqueue_after(struct malloc_chunk *after, struct malloc_chunk *chunk) {
    heap_assert(!in_use(chunk), "heap corruption (trying to enqueue in-use chunk)");
    heap_assert(!in_freelist(chunk), "heap corruption (trying to double-enqueue chunk)");
    after->fd->bk = chunk;
    chunk->fd = after->fd;
    chunk->bk = after;
    after->fd = chunk;
    chunk->flags |= MCF_FREELIST;
}

/// Remove a chunk from the freelist
static void unlink_chunk(struct malloc_chunk *chunk) {
    heap_assert(!in_use(chunk), "heap corruption (trying to unlink in-use chunk)");
    heap_assert(in_freelist(chunk), "heap corruption (trying to unlink already-unlinked chunk)");
    chunk->fd->bk = chunk->bk;
    chunk->bk->fd = chunk->fd;
    chunk->flags &= ~MCF_FREELIST;
}

/// Add a chunk to the arena freelist
static void enqueue_chunk(struct arena *arena, struct malloc_chunk *chunk) {
    if (is_top(chunk)) // By default, we want to avoid allocating from the top chunk, so insert that at the end always
        enqueue_before(&arena->freelist_head, chunk);
    else
        enqueue_after(&arena->freelist_head, chunk);
}

/// Initial size of the heap
#define INITIAL_HEAP_SIZE 0x20000

/// Size by multiples of which to extend the heap when it needs to grow
#define HEAP_GROWTH_INCREMENT 0x8000

/// Initial heap setup
static __attribute__((constructor)) void initialize(void) {
    // Allocate some heap memory from the system
    main_arena.start = sbrk(INITIAL_HEAP_SIZE);
    heap_assert(main_arena.start != (void *) -1, "failed to initialize heap (bad program break)");
    main_arena.end = sbrk(0);
    heap_assert(main_arena.end != (void *) -1, "failed to initialize heap (bad program break after resize)");
    heap_assert((char *) main_arena.end - (char *) main_arena.start == INITIAL_HEAP_SIZE, "failed to initialize heap (inaccurate resize)");

    // Initialize the freelist
    main_arena.freelist_head.fd = &main_arena.freelist_head;
    main_arena.freelist_head.bk = &main_arena.freelist_head;

    // Create the first chunk
    struct malloc_chunk *initial = (struct malloc_chunk *) main_arena.start;
    initial->next = (uintptr_t) main_arena.end;
    initial->flags = MCF_FIRST | MCF_TOP;
    enqueue_chunk(&main_arena, initial);
}

/// Grow the heap by adding more system memory, if needed.
static struct malloc_chunk *grow_top(struct arena *arena, size_t grow_by) {
    // Grab the top chunk
    struct malloc_chunk *top = arena->freelist_head.bk;
    heap_assert(is_top(top) && in_freelist(top), "heap corruption (no top chunk in freelist)");

    // Round up the allocation size
    grow_by += (HEAP_GROWTH_INCREMENT - (grow_by % HEAP_GROWTH_INCREMENT)) % HEAP_GROWTH_INCREMENT;
    heap_assert(grow_by, "failed to grow heap (overflow)");

    // Allocate more memory
    void *previous_brk = sbrk(grow_by);
    if (previous_brk == (void *) -1)
        return NULL;
    heap_assert(previous_brk == main_arena.end, "failed to grow heap (bad program break)");
    main_arena.end = sbrk(0);
    heap_assert(main_arena.end != (void *) -1, "failed to grow heap (bad program break after resize)");
    heap_assert((char *) main_arena.end - (char *) previous_brk == (ptrdiff_t) grow_by, "failed to grow heap (inaccurate resize)");

    // Resize the top chunk.
    top->next = (uintptr_t) main_arena.end;
    return top;
}

/// Split a chunk into two smaller chunks. Returns the right (back) chunk, the left (front) chunk stays in the same place.
/// The new chunk is _not_ yet enqueued in any list.
static struct malloc_chunk *split_chunk(struct malloc_chunk *left, size_t new_left_size) {
    heap_assert(!in_use(left), "heap corruption (splitting in-use chunk)");
    heap_assert((new_left_size & 0xf) == 0, "heap corruption (bad chunk size request)");
    struct malloc_chunk *right = (struct malloc_chunk *) ((char *) left + new_left_size);
    heap_assert(right < next_chunk(left), "heap corruption (chunk too small to split)");

    right->prev = left;
    right->next = left->next;
    right->flags = 0;
    if (is_top(left)) {
        // Splitting the top chunk makes a few things easier: there's no further chunk to update
        right->flags |= MCF_TOP;
        left->flags &= ~MCF_TOP;
    } else {
        struct malloc_chunk *beyond = next_chunk(left);
        heap_assert(!prev_in_use(beyond), "heap corruption (bad prev-in-use)");
        heap_assert(previous_chunk(beyond) == left, "heap corruption (bad prev)");
        beyond->prev = right;
    }
    left->next = (uintptr_t) right;
    return right;
}

/// Try to take a matching chunk out of the freelist.
/// If there is no chunk there, try to split the closest one (or, worst-case, the top chunk).
/// If that doesn't work either, we'll need to grow the heap.
static struct malloc_chunk *allocate_chunk(struct arena *arena, size_t new_size) {
    heap_assert((new_size & 0xf) == 0, "heap corruption (bad chunk size request)");
    struct malloc_chunk *target = NULL;
    for (struct malloc_chunk *chunk = arena->freelist_head.fd; chunk != &arena->freelist_head; chunk = fd_chunk(chunk)) {
        size_t size = chunk_size(chunk);
        if (size < new_size) {
            continue;
        } else if (!is_top(chunk) && size < new_size + sizeof(struct malloc_chunk)) {
            // This chunk is a close-enough fit that we can't split it further.
            // It's also not the top chunk.
            unlink_chunk(chunk);
            target = chunk;
            goto selected;
        }
        if (!target || is_top(target) || (!is_top(chunk) && size < chunk_size(target))) {
            // This chunk is large enough that we should keep looking, but it's the closest we've seen so far.
            // But we're enforcing splitting, so make sure it's also large enough.
            if (size >= new_size + sizeof(struct malloc_chunk))
                target = chunk;
        }
    }
    if (!target) {
        // We don't have enough space, so we need to grow the heap, and thus the top chunk.
        target = grow_top(arena, new_size + sizeof(struct malloc_chunk));
        if (!target)
            return NULL; // Out of memory.
    }

    // This chunk needs to be split.
    struct malloc_chunk *bk = bk_chunk(target);
    struct malloc_chunk *remainder = split_chunk(target, new_size);
    unlink_chunk(target);
    enqueue_after(bk, remainder);

selected:
    heap_assert(!is_top(target), "heap corruption (allocating top chunk)");
    heap_assert(!in_freelist(target), "heap corruption (chunk is still in freelist)");
    heap_assert(!in_use(target), "heap corruption (chunk is in use)");

    struct malloc_chunk *beyond = next_chunk(target);
    heap_assert(!prev_in_use(beyond), "heap corruption (bad prev-in-use)");
    heap_assert(previous_chunk(beyond) == target, "heap corruption (bad prev)");

    target->flags |= MCF_INUSE;
    beyond->flags |= MCF_PREVINUSE;
    return target;
}

/// Consolidate a chunk with the chunk to its right.
static struct malloc_chunk *consolidate_right(struct malloc_chunk *left) {
    heap_assert(!is_top(left), "heap corruption (consolidating beyond top chunk)");

    struct malloc_chunk *right = next_chunk(left);
    heap_assert(!in_use(left) && !in_use(right), "heap corruption (consolidating in-use chunk)");
    heap_assert(!prev_in_use(right), "heap corruption (bad prev-in-use)");
    heap_assert(previous_chunk(right) == left, "heap corruption (bad prev)");

    // Make sure that if either chunk is on the freelist the new chunk is also there
    if (in_freelist(right)) {
        struct malloc_chunk *bk = right->bk;
        unlink_chunk(right);
        if (!in_freelist(left))
            enqueue_after(bk, left);
    }

    left->next = right->next;
    if (is_top(right)) {
        left->flags |= MCF_TOP;
    } else {
        struct malloc_chunk *beyond = next_chunk(right);
        heap_assert(!prev_in_use(beyond), "heap corruption (bad prev-in-use)");
        heap_assert(previous_chunk(beyond) == right, "heap corruption (bad prev)");
        beyond->prev = left;
    }
    return left;
}

/// Consolidate a chunk with the chunk to its left.
static struct malloc_chunk *consolidate_left(struct malloc_chunk *right) {
    heap_assert(!is_first(right), "heap corruption (consolidating beyond first chunk)");
    heap_assert(!in_use(right) && !prev_in_use(right), "heap corruption (consolidating in-use chunk)");
    return consolidate_right(previous_chunk(right));
}

/// Keep consolidating a chunk with the chunks around it, until it can't be consolidated any further
static struct malloc_chunk *consolidate_chunk(struct malloc_chunk *chunk) {
    while (!is_top(chunk) && !in_use(next_chunk(chunk)))
        chunk = consolidate_right(chunk);
    while (!is_first(chunk) && !prev_in_use(chunk))
        chunk = consolidate_left(chunk);
    return chunk;
}

/// Return a chunk to the allocator
static void return_chunk(struct arena *arena, struct malloc_chunk *chunk) {
    heap_assert(in_use(chunk), "heap corruption (double free)");

    struct malloc_chunk *beyond = next_chunk(chunk);
    heap_assert(prev_in_use(beyond), "heap corruption (bad prev-in-use)");
    beyond->prev = chunk;
    beyond->flags &= ~MCF_PREVINUSE;

    chunk->flags &= ~MCF_INUSE;
    chunk = consolidate_chunk(chunk);
    if (!in_freelist(chunk))
        enqueue_chunk(arena, chunk);
}

/// Convert the size of a malloc() request to the actual size of the underlying chunk (which counts the overlap!)
static inline __attribute__((always_inline)) size_t request_size_to_chunk_size(size_t request_size) {
    size_t with_header = request_size + offsetof(struct malloc_chunk, user_data) - offsetof(struct malloc_chunk, chunk_header);
    with_header = with_header < sizeof(struct malloc_chunk) ? sizeof(struct malloc_chunk) : with_header;
    return with_header + ((0x10 - (with_header & 0xf)) & 0xf);
}

/// Get the usable amount of memory behind a malloc(3) allocation. This isn't in POSIX but some GNU stuff uses it, and we can use it below.
size_t malloc_usable_size(void *ptr) {
    struct malloc_chunk *chunk = chunk_for(ptr);
    heap_assert(in_use(chunk), "heap corruption (double free: reallocating unused chunk)");
    return usable_size(chunk_size(chunk));
}

/// This is just malloc(), but only used internally to avoid compilers being too smart (see calloc() below).
static void *internal_malloc(size_t size) {
    if (size <= 0) return NULL; // POSIX says this is OK.
    struct malloc_chunk *chunk = allocate_chunk(&main_arena, request_size_to_chunk_size(size));
    if (!chunk) { errno = ENOMEM; return NULL; }
    return user_data(chunk);
}

/// Allocate some memory. See malloc(3).
void *malloc(size_t size) {
    return internal_malloc(size);
}

/// Free some memory. See malloc(3).
void free(void *ptr) {
    if (!ptr) return; // (a) NULL is always OK to free, and (b) we hand out NULL for malloc(0).
    return_chunk(&main_arena, chunk_for(ptr));
}

/// Resize the memory allocation. See malloc(3) for more details.
void *realloc(void *ptr, size_t size) {
    if (!size) { free(ptr); return NULL; } // Size 0 is equivalent to freeing the memory
    if (!ptr) return internal_malloc(size); // If we don't have a pointer yet, just allocate

    size_t usable = malloc_usable_size(ptr);
    if (usable >= size) return ptr; // No need to reallocate, chunk is large enough

    void *new = internal_malloc(size);
    if (!new) return NULL; // On error, don't free ptr.

    memcpy(new, ptr, usable);
    free(ptr);
    return new;
}

// calloc and reallocarray really just make sure the multiplication does not overflow
// (calloc also zeroes the memory). See malloc(3) for more details.
void *calloc(size_t nmemb, size_t size) {
    if (__builtin_umull_overflow(nmemb, size, &size)) { errno = ENOMEM; return NULL; }
    void *memory = internal_malloc(size); // This can't be malloc directly since the compiler will optimize this + memset to calloc.
    return memory ? memset(memory, 0, size) : NULL;
}

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
    if (__builtin_umull_overflow(nmemb, size, &size)) { errno = ENOMEM; return NULL; }
    return realloc(ptr, size);
}

// Other POSIX/libc functions that I haven't implemented because I don't want to bloat this even further
#pragma GCC diagnostic ignored "-Wunused-parameter"

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    errx(EXIT_FAILURE, "posix_memalign: not implemented");
}
void *aligned_alloc(size_t alignment, size_t size) {
    errx(EXIT_FAILURE, "aligned_alloc: not implemented");
}
__attribute__((deprecated)) void *memalign(size_t alignment, size_t size) {
    errx(EXIT_FAILURE, "memalign: not implemented");
}
__attribute__((deprecated)) void *pvalloc(size_t size) {
    errx(EXIT_FAILURE, "pvalloc: not implemented");
}
__attribute__((deprecated)) void *valloc(size_t size) {
    errx(EXIT_FAILURE, "valloc: not implemented");
}
