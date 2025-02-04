# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "unsorted"
- story: 
    - In the lecture, we discussed that you might be able to move an unsortedbin chunk into a smallbin to avoid a lot of the checks. This means you need to try to allocate a chunk that is larger than the chunk that you have in the unsorted bin. One way to do this is to (ab)use the fact that scanf can actually allocate memory if its internal buffer (of 1024 bytes) fills up! You can find the function responsible for this here (https://elixir.bootlin.com/glibc/glibc-2.36.9000/source/stdio-common/vfscanf-internal.c#L236).
    - Bypassing the single remaining smallbin check (victim->bk->fd == victim) is still not trivial. You need to have a pointer to your chunk (not to the data!) somewhere that you know the address of. To make your life a little easier, you get a stack leak for this. Think about what data you can control there!
    - tcaches are disabled, so you can't just overwrite a tcache next pointer.

# overview
- global notes array with 16 pointers to notes
- ADD allocates 256 bytes (actually 264 bytes) and we can write up to 256 byte note
- DELETE free()'s a note, but pointer stays in global array => use after free possible
- SHOW simply prints where the pointer in the array points to
- EDIT allows to change the 256 bytes content of note

# attack idea
- free my note chunk (272 bytes size) (is put in unsorted)
- allocate big chunk via scanf => freed()'ed chunk is put in smallbins
- write after free => override next and prev pointer
    - next: keep same (we leaked it)
    - override prev pointer with stack address
    - on stack, where victim.bk.fd is expected, there needs to be the address of our victim
- now victim is in smallbins
- write after free again, to override next pointer (now in smallbins) again to custom address on stack
- write ropchain there
- done

# smallbin code: 
- https://elixir.bootlin.com/glibc/glibc-2.36.9000/source/malloc/malloc.c#L3899
```c
 if (in_smallbin_range (nb)) // we are in a smallbin
    {
        idx = smallbin_index (nb);
        bin = bin_at (av, idx);     // the smallbin for our size

        if ((victim = last (bin)) != bin) // we start at last
        {

            // single sanity check that: victim->bk->fd == victim
            bck = victim->bk;
            if (__glibc_unlikely (bck->fd != victim))
                malloc_printerr ("malloc(): smallbin double linked list corrupted");
            
            set_inuse_bit_at_offset (victim, nb);

            // update linked list
            bin->bk = bck;
            bck->fd = bin;

            if (av != &main_arena)
                set_non_main_arena (victim);
            
            // checks that size and flags are correct
            check_malloced_chunk (av, victim, nb);

            // get memory pointer for user
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
        }
    }
```
- we write size, fd and bk (24) Byte into buf 


# flag
```
softsec{uZWuLdt77Z1n-dYk2wtigrRS_PQ6-8GajOgx5eUrR81yLUv876GvoL4drJ5hTP_6}
```
