
#pragma once

#include "HashTypes.h"

#include <cstddef>

/**
 * The Keccak-f[800] function.
 *
 * The implementation of the Keccak-f function with 800-bit width of the permutation (b).
 * The size of the state is also 800 bit what gives 25 32-bit words.
 *
 * @param state  The state of 25 32-bit words on which the permutation is to be performed.
 */
void ethash_keccakf800(uint32_t state[25]) noexcept;

union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size) noexcept;
union ethash_hash256 ethash_keccak256_32(const uint8_t data[32]) noexcept;
union ethash_hash512 ethash_keccak512(const uint8_t* data, size_t size) noexcept;
union ethash_hash512 ethash_keccak512_64(const uint8_t data[64]) noexcept;

namespace ethash
{
    inline hash256 keccak256(const uint8_t* data, size_t size) noexcept
    {
        return ethash_keccak256(data, size);
    }

    inline hash256 keccak256(const hash256& input) noexcept
    {
        return ethash_keccak256_32(input.bytes);
    }

    inline hash512 keccak512(const uint8_t* data, size_t size) noexcept
    {
        return ethash_keccak512(data, size);
    }

    inline hash512 keccak512(const hash512& input) noexcept
    {
        return ethash_keccak512_64(input.bytes);
    }

    static constexpr auto keccak256_32 = ethash_keccak256_32;
    static constexpr auto keccak512_64 = ethash_keccak512_64;

}  // namespace ethash