#pragma once

#include "HashTypes.h"

#include <cstdint>
#include <cstring>
#include <memory>

/**
 * The Ethash algorithm revision implemented as specified in the Ethash spec
 * https://github.com/ethereum/wiki/wiki/Ethash.
 */

/** FNV 32-bit prime. */
static const uint32_t fnv_prime = 0x01000193;

/** FNV 32-bit offset basis. */
static const uint32_t fnv_offset_basis = 0x811c9dc5;

/**
 * The implementation of FNV-1 hash.
 *
 * See https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#FNV-1_hash.
 */
inline uint32_t fnv1(uint32_t u, uint32_t v) noexcept {
    return (u * fnv_prime) ^ v;
}

/**
 * The implementation of FNV-1a hash.
 *
 * See https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#FNV-1a_hash.
 */
inline uint32_t fnv1a(uint32_t u, uint32_t v) noexcept {
    return (u ^ v) * fnv_prime;
}

struct ethash_epoch_context {
    const int epoch_number;
    const int light_cache_num_items;
    const union ethash_hash512 *const light_cache;
    const uint32_t *const l1_cache;
    const int full_dataset_num_items;
};

struct ethash_epoch_context_full;


struct ethash_result {
    union ethash_hash256 final_hash;
    union ethash_hash256 mix_hash;
};


/**
 * Calculates the number of items in the light cache for given epoch.
 *
 * This function will search for a prime number matching the criteria given
 * by the Ethash so the execution time is not constant. It takes ~ 0.01 ms.
 *
 * @param epoch_number  The epoch number.
 * @return              The number items in the light cache.
 */
int ethash_calculate_light_cache_num_items(int epoch_number) noexcept;


/**
 * Calculates the number of items in the full dataset for given epoch.
 *
 * This function will search for a prime number matching the criteria given
 * by the Ethash so the execution time is not constant. It takes ~ 0.05 ms.
 *
 * @param epoch_number  The epoch number.
 * @return              The number items in the full dataset.
 */
int ethash_calculate_full_dataset_num_items(int epoch_number) noexcept;

/**
 * Calculates the epoch seed hash.
 * @param epoch_number  The epoch number.
 * @return              The epoch seed hash.
 */
union ethash_hash256 ethash_calculate_epoch_seed(int epoch_number) noexcept;

struct ethash_epoch_context *ethash_create_epoch_context(int epoch_number) noexcept;

/**
 * Creates the epoch context with the full dataset initialized.
 *
 * The memory for the full dataset is only allocated and marked as "not-generated".
 * The items of the full dataset are generated on the fly when hit for the first time.
 *
 * The memory allocated in the context MUST be freed with ethash_destroy_epoch_context_full().
 *
 * @param epoch_number  The epoch number.
 * @return  Pointer to the context or null in case of memory allocation failure.
 */
struct ethash_epoch_context_full *ethash_create_epoch_context_full(int epoch_number) noexcept;

void ethash_destroy_epoch_context(struct ethash_epoch_context *context) noexcept;

void ethash_destroy_epoch_context_full(struct ethash_epoch_context_full *context) noexcept;

/**
 * Get global shared epoch context.
 */
const struct ethash_epoch_context *ethash_get_global_epoch_context(int epoch_number) noexcept;

/**
 * Get global shared epoch context with full dataset initialized.
 */
const struct ethash_epoch_context_full *ethash_get_global_epoch_context_full(int epoch_number) noexcept;


struct ethash_result ethash_hash(const struct ethash_epoch_context *context,
                                 const union ethash_hash256 *header_hash, uint64_t nonce) noexcept;

bool ethash_verify(const struct ethash_epoch_context *context,
                   const union ethash_hash256 *header_hash, const union ethash_hash256 *mix_hash, uint64_t nonce,
                   const union ethash_hash256 *boundary) noexcept;

bool ethash_verify_final_hash(const union ethash_hash256 *header_hash,
                              const union ethash_hash256 *mix_hash, uint64_t nonce,
                              const union ethash_hash256 *boundary) noexcept;

namespace ethash {
    constexpr auto revision = "23";

    static constexpr int epoch_length = 30000;
    static constexpr int light_cache_item_size = 64;
    static constexpr int full_dataset_item_size = 128;
    static constexpr int num_dataset_accesses = 64;

    using epoch_context = ethash_epoch_context;
    using epoch_context_full = ethash_epoch_context_full;

    using result = ethash_result;

    /// Constructs a 256-bit hash from an array of bytes.
    ///
    /// @param bytes  A pointer to array of at least 32 bytes.
    /// @return       The constructed hash.
    inline hash256 hash256_from_bytes(const uint8_t bytes[32]) noexcept {
        hash256 h;
        std::memcpy(&h, bytes, sizeof(h));
        return h;
    }

    struct search_result {
        bool solution_found = false;
        uint64_t nonce = 0;
        hash256 final_hash = {};
        hash256 mix_hash = {};

        search_result() noexcept = default;

        search_result(result res, uint64_t n) noexcept
                : solution_found(true), nonce(n), final_hash(res.final_hash), mix_hash(res.mix_hash) {}
    };


    /// Alias for ethash_calculate_light_cache_num_items().
    static constexpr auto calculate_light_cache_num_items = ethash_calculate_light_cache_num_items;

    /// Alias for ethash_calculate_full_dataset_num_items().
    static constexpr auto calculate_full_dataset_num_items = ethash_calculate_full_dataset_num_items;

    /// Alias for ethash_calculate_epoch_seed().
    static constexpr auto calculate_epoch_seed = ethash_calculate_epoch_seed;


    /// Calculates the epoch number out of the block number.
    inline constexpr int get_epoch_number(int block_number) noexcept {
        return block_number / epoch_length;
    }

    /**
     * Coverts the number of items of a light cache to size in bytes.
     *
     * @param num_items  The number of items in the light cache.
     * @return           The size of the light cache in bytes.
     */
    inline constexpr size_t get_light_cache_size(int num_items) noexcept {
        return static_cast<size_t>(num_items) * light_cache_item_size;
    }

    /**
     * Coverts the number of items of a full dataset to size in bytes.
     *
     * @param num_items  The number of items in the full dataset.
     * @return           The size of the full dataset in bytes.
     */
    inline constexpr uint64_t get_full_dataset_size(int num_items) noexcept {
        return static_cast<uint64_t>(num_items) * full_dataset_item_size;
    }

    /// Owned unique pointer to an epoch context.
    using epoch_context_ptr = std::unique_ptr<epoch_context, decltype(&ethash_destroy_epoch_context)>;

    using epoch_context_full_ptr =
    std::unique_ptr<epoch_context_full, decltype(&ethash_destroy_epoch_context_full)>;

    /// Creates Ethash epoch context.
    ///
    /// This is a wrapper for ethash_create_epoch_number C function that returns
    /// the context as a smart pointer which handles the destruction of the context.
    inline epoch_context_ptr create_epoch_context(int epoch_number) noexcept {
        return {ethash_create_epoch_context(epoch_number), ethash_destroy_epoch_context};
    }

    inline epoch_context_full_ptr create_epoch_context_full(int epoch_number) noexcept {
        return {ethash_create_epoch_context_full(epoch_number), ethash_destroy_epoch_context_full};
    }


    inline result hash(
            const epoch_context &context, const hash256 &header_hash, uint64_t nonce) noexcept {
        return ethash_hash(&context, &header_hash, nonce);
    }

    result hash(const epoch_context_full &context, const hash256 &header_hash, uint64_t nonce) noexcept;

    inline bool verify_final_hash(const hash256 &header_hash, const hash256 &mix_hash, uint64_t nonce,
                                  const hash256 &boundary) noexcept {
        return ethash_verify_final_hash(&header_hash, &mix_hash, nonce, &boundary);
    }

    inline bool verify(const epoch_context &context, const hash256 &header_hash, const hash256 &mix_hash,
                       uint64_t nonce, const hash256 &boundary) noexcept {
        return ethash_verify(&context, &header_hash, &mix_hash, nonce, &boundary);
    }

    search_result search_light(const epoch_context &context, const hash256 &header_hash,
                               const hash256 &boundary, uint64_t start_nonce, size_t iterations) noexcept;

    search_result search(const epoch_context_full &context, const hash256 &header_hash,
                         const hash256 &boundary, uint64_t start_nonce, size_t iterations) noexcept;


    /// Tries to find the epoch number matching the given seed hash.
    ///
    /// Mining pool protocols (many variants of stratum and "getwork") send out
    /// seed hash instead of epoch number to workers. This function tries to recover
    /// the epoch number from this seed hash.
    ///
    /// @param seed  Ethash seed hash.
    /// @return      The epoch number or -1 if not found.
    int find_epoch_number(const hash256 &seed) noexcept;


    /// Get global shared epoch context.
    inline const epoch_context &get_global_epoch_context(int epoch_number) noexcept {
        return *ethash_get_global_epoch_context(epoch_number);
    }

    /// Get global shared epoch context with full dataset initialized.
    inline const epoch_context_full &get_global_epoch_context_full(int epoch_number) noexcept {
        return *ethash_get_global_epoch_context_full(epoch_number);
    }
}  // namespace ethash
