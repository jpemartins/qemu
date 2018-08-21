/*
 * x86-specific Atomic Bitops Module
 *
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * Taken from Xen.
 *
 * This work is licensed under the terms of the GNU GPLv2.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef X86_BITOPS_H
#define X86_BITOPS_H

/**
 * clear_bit_atomic - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit_atomic() is atomic and may not be reordered.
 */
static inline void clear_bit_atomic(int nr, volatile void *addr)
{
    asm volatile ( "lock; btrl %1,%0"
                   : "+m" ((*(volatile long *) addr)) : "Ir" (nr) : "memory");
}

/**
 * test_and_set_bit_atomic - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int test_and_set_bit_atomic(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile (
        "lock; btsl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" ((*(volatile long *) addr))
        : "Ir" (nr), "m" ((*(volatile long *) addr)) : "memory");
    return oldbit;
}


/**
 * test_and_clear_bit_atomic - Clear a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int test_and_clear_bit_atomic(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile (
        "lock; btrl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" ((*(volatile long *) addr))
        : "Ir" (nr), "m" ((*(volatile long *) addr)) : "memory");
    return oldbit;
}

#endif /* X86_BITOPS_H */

