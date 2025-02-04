# This is a bit like pwndbg's heap commands for this custom allocator.
import gdb

class InspectHeap(gdb.Command):
    '''inspect-heap [chunk address]'''
    def __init__(self):
        super().__init__('inspect-heap', gdb.COMMAND_OBSCURE, gdb.COMPLETE_EXPRESSION)

    def invoke(self, argument, from_tty):
        _ = from_tty
        argument = argument.strip()
        heap_start = int(gdb.parse_and_eval('main_arena.start'))
        heap_end = int(gdb.parse_and_eval('main_arena.end'))
        if argument:
            actual_start = int(gdb.parse_and_eval(argument))
            if heap_start <= actual_start <= heap_end:
                actual_end = heap_end
            else:
                actual_end = actual_start + 1
            heap_start, heap_end = actual_start, actual_end

        freelist_head = int(gdb.parse_and_eval('&main_arena.freelist_head'))
        chunk = heap_start
        while chunk < heap_end:
            prev = int(gdb.parse_and_eval(f'((struct malloc_chunk *) {chunk:#x})->prev'))
            next_ = int(gdb.parse_and_eval(f'((struct malloc_chunk *) {chunk:#x})->next'))
            flags = gdb.parse_and_eval(f'((struct malloc_chunk *) {chunk:#x})->flags')
            fd = int(gdb.parse_and_eval(f'((struct malloc_chunk *) {chunk:#x})->fd'))
            bk = int(gdb.parse_and_eval(f'((struct malloc_chunk *) {chunk:#x})->bk'))

            if int(flags) & 0x1: # MCF_INUSE
                head = f'\x1b[33mAllocated chunk at {chunk:#x}\x1b[0m'
            elif int(flags) & 0x4: # MCF_TOP
                head = f'\x1b[31mTop chunk at {chunk:#x}\x1b[0m'
            elif int(flags) & 0x10: # MCF_FREELIST
                head = f'\x1b[32mFree chunk at {chunk:#x}\x1b[0m'
            else:
                head = f'\x1b[35mWeird chunk at {chunk:#x}\x1b[0m'
            print(head)

            if not (int(flags) & 0xa): # MCF_PREVINUSE | MCF_FIRST
                print(f' - prev:  \x1b[34m{prev:#x}\x1b[0m ({chunk - prev:#x} bytes)')
            print(f' - next:  \x1b[34m{next_:#x}\x1b[0m ({next_ - chunk:#x} bytes)')
            print(f' - flags: {flags}')
            if int(flags) & 0x10: # MCF_FREELIST
                arena_tag = lambda ptr: ' (arena)' if ptr == freelist_head else ''
                arena_color = lambda ptr: '\x1b[35m' if ptr == freelist_head else '\x1b[34m'
                print(f' - fd:    {arena_color(fd)}{fd:#x}\x1b[0m' + arena_tag(fd))
                print(f' - bk:    {arena_color(bk)}{bk:#x}\x1b[0m' + arena_tag(bk))
            print()
            if next_ <= chunk:
                print(f'\x1b[31;1mbad next pointer\x1b[0m\n')
                break
            chunk = next_

InspectHeap()

class InspectFreelist(gdb.Command):
    '''inspect-freelist'''
    def __init__(self):
        super().__init__('inspect-freelist', gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def invoke(self, argument, from_tty):
        _ = from_tty
        _ = argument
        freelist_head = int(gdb.parse_and_eval('&main_arena.freelist_head'))
        get_fd = lambda chunk: int(gdb.parse_and_eval(f'((struct malloc_chunk *) {chunk})->fd'))

        print('\x1b[1mfreelist\x1b[0m', end='')
        chunk = get_fd(freelist_head)
        while chunk != freelist_head:
            flags = int(gdb.parse_and_eval(f'((struct malloc_chunk *) {chunk})->flags'))
            print(' → ', end='')
            end = ''
            if flags & 0x1: # MCF_INUSE
                print('\x1b[31min use: ', end='')
                end = '\x1b[0m'
            if flags & 0x4: # MCF_TOP
                print('\x1b[36mtop: ', end='')
                end = '\x1b[0m'
            if not (flags & 0x10): # not MCF_FREELIST
                print('\x1b[33mnot on freelist: ', end='')
                end = '\x1b[0m'
            print(f'{chunk:#x}', end=end)
            chunk = get_fd(chunk)
        print()

InspectFreelist()
