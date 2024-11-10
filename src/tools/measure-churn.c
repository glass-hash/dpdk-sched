#define _GNU_SOURCE

#include <assert.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <rte_build_config.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_per_lcore.h>
#include <rte_thash.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <time.h>

#include "../log.h"

#define DROP ((uint16_t)-1)
#define FLOOD ((uint16_t)-2)

#define FLOW_CAPACITY 65536

#define time_t int64_t

time_t current_time(void) {
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return tp.tv_sec * 1000000000ul + tp.tv_nsec;
}

typedef unsigned map_key_hash(void *k1);
typedef bool map_keys_equality(void *k1, void *k2);

struct Map {
  int *busybits;
  void **keyps;
  unsigned *khs;
  int *chns;
  int *vals;
  unsigned capacity;
  unsigned size;
  map_keys_equality *keys_eq;
  map_key_hash *khash;
};

static unsigned loop(unsigned k, unsigned capacity) {
  return k & (capacity - 1);
}

static int find_key(int *busybits, void **keyps, unsigned *k_hashes, int *chns,
                    void *keyp, map_keys_equality *eq, unsigned key_hash,
                    unsigned capacity) {
  unsigned start = loop(key_hash, capacity);
  unsigned i = 0;
  for (; i < capacity; ++i) {
    unsigned index = loop(start + i, capacity);
    int bb = busybits[index];
    unsigned kh = k_hashes[index];
    int chn = chns[index];
    void *kp = keyps[index];
    if (bb != 0 && kh == key_hash) {
      if (eq(kp, keyp)) {
        return (int)index;
      }
    } else {
      if (chn == 0) {
        return -1;
      }
    }
  }

  return -1;
}

static unsigned find_key_remove_chain(int *busybits, void **keyps,
                                      unsigned *k_hashes, int *chns, void *keyp,
                                      map_keys_equality *eq, unsigned key_hash,
                                      unsigned capacity, void **keyp_out) {
  unsigned i = 0;
  unsigned start = loop(key_hash, capacity);

  for (; i < capacity; ++i) {
    unsigned index = loop(start + i, capacity);
    int bb = busybits[index];
    unsigned kh = k_hashes[index];
    int chn = chns[index];
    void *kp = keyps[index];
    if (bb != 0 && kh == key_hash) {
      if (eq(kp, keyp)) {
        busybits[index] = 0;
        *keyp_out = keyps[index];
        return index;
      }
    }

    chns[index] = chn - 1;
  }

  return -1;
}

static unsigned find_empty(int *busybits, int *chns, unsigned start,
                           unsigned capacity) {
  unsigned i = 0;
  for (; i < capacity; ++i) {
    unsigned index = loop(start + i, capacity);
    int bb = busybits[index];
    if (0 == bb) {
      return index;
    }

    int chn = chns[index];
    chns[index] = chn + 1;
  }

  return -1;
}

void map_impl_init(int *busybits, int *chns, unsigned capacity) {
  unsigned i = 0;
  for (; i < capacity; ++i) {
    busybits[i] = 0;
    chns[i] = 0;
  }
}

int map_impl_get(int *busybits, void **keyps, unsigned *k_hashes, int *chns,
                 int *values, void *keyp, map_keys_equality *eq, unsigned hash,
                 int *value, unsigned capacity) {
  int index =
      find_key(busybits, keyps, k_hashes, chns, keyp, eq, hash, capacity);
  if (-1 == index) {
    return 0;
  }

  *value = values[index];
  return 1;
}

void map_impl_put(int *busybits, void **keyps, unsigned *k_hashes, int *chns,
                  int *values, void *keyp, unsigned hash, int value,
                  unsigned capacity) {
  unsigned start = loop(hash, capacity);
  unsigned index = find_empty(busybits, chns, start, capacity);

  busybits[index] = 1;
  keyps[index] = keyp;
  k_hashes[index] = hash;
  values[index] = value;
}

void map_impl_erase(int *busybits, void **keyps, unsigned *k_hashes, int *chns,
                    void *keyp, map_keys_equality *eq, unsigned hash,
                    unsigned capacity, void **keyp_out) {
  find_key_remove_chain(busybits, keyps, k_hashes, chns, keyp, eq, hash,
                        capacity, keyp_out);
}

unsigned map_impl_size(int *busybits, unsigned capacity) {
  unsigned s = 0;
  unsigned i = 0;
  for (; i < capacity; ++i) {
    if (busybits[i] != 0) {
      ++s;
    }
  }
  return s;
}

int map_allocate(map_keys_equality *keq, map_key_hash *khash, unsigned capacity,
                 struct Map **map_out) {
  struct Map *old_map_val = *map_out;
  struct Map *map_alloc =
      (struct Map *)rte_malloc(NULL, sizeof(struct Map), 64);
  if (map_alloc == NULL) return 0;
  *map_out = (struct Map *)map_alloc;
  int *bbs_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);
  if (bbs_alloc == NULL) {
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->busybits = bbs_alloc;
  void **keyps_alloc =
      (void **)rte_malloc(NULL, sizeof(void *) * (int)capacity, 64);
  if (keyps_alloc == NULL) {
    rte_free(bbs_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->keyps = keyps_alloc;
  unsigned *khs_alloc =
      (unsigned *)rte_malloc(NULL, sizeof(unsigned) * (int)capacity, 64);
  if (khs_alloc == NULL) {
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->khs = khs_alloc;
  int *chns_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);
  if (chns_alloc == NULL) {
    rte_free(khs_alloc);
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->chns = chns_alloc;
  int *vals_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);

  if (vals_alloc == NULL) {
    rte_free(chns_alloc);
    rte_free(khs_alloc);
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }

  (*map_out)->vals = vals_alloc;
  (*map_out)->capacity = capacity;
  (*map_out)->size = 0;
  (*map_out)->keys_eq = keq;
  (*map_out)->khash = khash;

  map_impl_init((*map_out)->busybits, (*map_out)->chns, capacity);
  return 1;
}

int map_get(struct Map *map, void *key, int *value_out) {
  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  return map_impl_get(map->busybits, map->keyps, map->khs, map->chns, map->vals,
                      key, map->keys_eq, hash, value_out, map->capacity);
}

void map_put(struct Map *map, void *key, int value) {
  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  map_impl_put(map->busybits, map->keyps, map->khs, map->chns, map->vals, key,
               hash, value, map->capacity);
  ++map->size;
}

void map_erase(struct Map *map, void *key, void **trash) {
  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  map_impl_erase(map->busybits, map->keyps, map->khs, map->chns, key,
                 map->keys_eq, hash, map->capacity, trash);

  --map->size;
}

unsigned map_size(struct Map *map) { return map->size; }

// Makes sure the allocator structur fits into memory, && particularly into
// 32 bit address space.
#define IRANG_LIMIT (1048576)

// kinda hacky, but makes the proof independent of time_t... sort of
#define malloc_block_time malloc_block_llongs
#define time_integer llong_integer
#define times llongs

#define DCHAIN_RESERVED (2)

struct dchain_cell {
  int prev;
  int next;
};

struct DoubleChain {
  struct dchain_cell *cells;
  time_t *timestamps;
};

enum DCHAIN_ENUM {
  ALLOC_LIST_HEAD = 0,
  FREE_LIST_HEAD = 1,
  INDEX_SHIFT = DCHAIN_RESERVED
};

void dchain_impl_init(struct dchain_cell *cells, int size) {
  struct dchain_cell *al_head = cells + ALLOC_LIST_HEAD;
  al_head->prev = 0;
  al_head->next = 0;
  int i = INDEX_SHIFT;

  struct dchain_cell *fl_head = cells + FREE_LIST_HEAD;
  fl_head->next = i;
  fl_head->prev = fl_head->next;

  while (i < (size + INDEX_SHIFT - 1)) {
    struct dchain_cell *current = cells + i;
    current->next = i + 1;
    current->prev = current->next;

    ++i;
  }

  struct dchain_cell *last = cells + i;
  last->next = FREE_LIST_HEAD;
  last->prev = last->next;
}

int dchain_impl_allocate_new_index(struct dchain_cell *cells, int *index) {
  struct dchain_cell *fl_head = cells + FREE_LIST_HEAD;
  struct dchain_cell *al_head = cells + ALLOC_LIST_HEAD;
  int allocated = fl_head->next;
  if (allocated == FREE_LIST_HEAD) {
    return 0;
  }

  struct dchain_cell *allocp = cells + allocated;
  // Extract the link from the "empty" chain.
  fl_head->next = allocp->next;
  fl_head->prev = fl_head->next;

  // Add the link to the "new"-end "alloc" chain.
  allocp->next = ALLOC_LIST_HEAD;
  allocp->prev = al_head->prev;

  struct dchain_cell *alloc_head_prevp = cells + al_head->prev;
  alloc_head_prevp->next = allocated;
  al_head->prev = allocated;

  *index = allocated - INDEX_SHIFT;

  return 1;
}

int dchain_impl_free_index(struct dchain_cell *cells, int index) {
  int freed = index + INDEX_SHIFT;

  struct dchain_cell *freedp = cells + freed;
  int freed_prev = freedp->prev;
  int freed_next = freedp->next;

  // The index is already free.
  if (freed_next == freed_prev) {
    if (freed_prev != ALLOC_LIST_HEAD) {
      return 0;
    }
  }

  struct dchain_cell *fr_head = cells + FREE_LIST_HEAD;
  struct dchain_cell *freed_prevp = cells + freed_prev;
  freed_prevp->next = freed_next;

  struct dchain_cell *freed_nextp = cells + freed_next;
  freed_nextp->prev = freed_prev;

  freedp->next = fr_head->next;
  freedp->prev = freedp->next;

  fr_head->next = freed;
  fr_head->prev = fr_head->next;

  return 1;
}

int dchain_impl_get_oldest_index(struct dchain_cell *cells, int *index) {
  struct dchain_cell *al_head = cells + ALLOC_LIST_HEAD;

  // No allocated indexes.
  if (al_head->next == ALLOC_LIST_HEAD) {
    return 0;
  }

  *index = al_head->next - INDEX_SHIFT;

  return 1;
}

int dchain_impl_rejuvenate_index(struct dchain_cell *cells, int index) {
  int lifted = index + INDEX_SHIFT;

  struct dchain_cell *liftedp = cells + lifted;
  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  if (lifted_next == lifted_prev) {
    if (lifted_next != ALLOC_LIST_HEAD) {
      return 0;
    } else {
      return 1;
    }
  }

  struct dchain_cell *lifted_prevp = cells + lifted_prev;
  lifted_prevp->next = lifted_next;

  struct dchain_cell *lifted_nextp = cells + lifted_next;
  lifted_nextp->prev = lifted_prev;

  struct dchain_cell *al_head = cells + ALLOC_LIST_HEAD;
  int al_head_prev = al_head->prev;

  liftedp->next = ALLOC_LIST_HEAD;
  liftedp->prev = al_head_prev;

  struct dchain_cell *al_head_prevp = cells + al_head_prev;
  al_head_prevp->next = lifted;

  al_head->prev = lifted;
  return 1;
}

int dchain_impl_is_index_allocated(struct dchain_cell *cells, int index) {
  int lifted = index + INDEX_SHIFT;

  struct dchain_cell *liftedp = cells + lifted;
  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  if (lifted_next == lifted_prev) {
    if (lifted_next != ALLOC_LIST_HEAD) {
      return 0;
    } else {
      return 1;
    }
  } else {
    return 1;
  }
}

int dchain_allocate(int index_range, struct DoubleChain **chain_out) {
  struct DoubleChain *old_chain_out = *chain_out;
  struct DoubleChain *chain_alloc =
      (struct DoubleChain *)rte_malloc(NULL, sizeof(struct DoubleChain), 64);
  if (chain_alloc == NULL) return 0;
  *chain_out = (struct DoubleChain *)chain_alloc;

  struct dchain_cell *cells_alloc = (struct dchain_cell *)rte_malloc(
      NULL, sizeof(struct dchain_cell) * (index_range + DCHAIN_RESERVED), 64);
  if (cells_alloc == NULL) {
    rte_free(chain_alloc);
    *chain_out = old_chain_out;
    return 0;
  }
  (*chain_out)->cells = cells_alloc;

  time_t *timestamps_alloc =
      (time_t *)rte_malloc(NULL, sizeof(time_t) * (index_range), 64);
  if (timestamps_alloc == NULL) {
    rte_free((void *)cells_alloc);
    rte_free(chain_alloc);
    *chain_out = old_chain_out;
    return 0;
  }
  (*chain_out)->timestamps = timestamps_alloc;

  dchain_impl_init((*chain_out)->cells, index_range);

  return 1;
}

int dchain_allocate_new_index(struct DoubleChain *chain, int *index_out,
                              time_t time) {
  int ret = dchain_impl_allocate_new_index(chain->cells, index_out);

  if (ret) {
    chain->timestamps[*index_out] = time;
  }

  return ret;
}

int dchain_rejuvenate_index(struct DoubleChain *chain, int index, time_t time) {
  int ret = dchain_impl_rejuvenate_index(chain->cells, index);

  if (ret) {
    chain->timestamps[index] = time;
  }

  return ret;
}

int dchain_expire_one_index(struct DoubleChain *chain, int *index_out,
                            time_t time) {
  int has_ind = dchain_impl_get_oldest_index(chain->cells, index_out);

  if (has_ind) {
    if (chain->timestamps[*index_out] < time) {
      int rez = dchain_impl_free_index(chain->cells, *index_out);
      return rez;
    }
  }

  return 0;
}

int dchain_is_index_allocated(struct DoubleChain *chain, int index) {
  return dchain_impl_is_index_allocated(chain->cells, index);
}

int dchain_free_index(struct DoubleChain *chain, int index) {
  return dchain_impl_free_index(chain->cells, index);
}

#define VECTOR_CAPACITY_UPPER_LIMIT 140000

typedef void vector_init_elem(void *elem);

struct Vector {
  char *data;
  int elem_size;
  unsigned capacity;
};

int vector_allocate(int elem_size, unsigned capacity,
                    vector_init_elem *init_elem, struct Vector **vector_out) {
  struct Vector *old_vector_val = *vector_out;
  struct Vector *vector_alloc =
      (struct Vector *)rte_malloc(NULL, sizeof(struct Vector), 64);
  if (vector_alloc == 0) return 0;
  *vector_out = (struct Vector *)vector_alloc;

  char *data_alloc =
      (char *)rte_malloc(NULL, (uint32_t)elem_size * capacity, 64);
  if (data_alloc == 0) {
    rte_free(vector_alloc);
    *vector_out = old_vector_val;
    return 0;
  }
  (*vector_out)->data = data_alloc;
  (*vector_out)->elem_size = elem_size;
  (*vector_out)->capacity = capacity;

  for (unsigned i = 0; i < capacity; ++i) {
    if (init_elem) {
      init_elem((*vector_out)->data + elem_size * (int)i);
    }
  }

  return 1;
}

void vector_get(struct Vector *vector, int index, void **val_out) {
  *val_out = vector->data + index * vector->elem_size;
}

int expire_items_single_map(struct DoubleChain *chain, struct Vector *vector,
                            struct Map *map, time_t time) {
  int count = 0;
  int index = -1;

  while (dchain_expire_one_index(chain, &index, time)) {
    void *key;
    vector_get(vector, index, &key);
    map_erase(map, key, &key);

    ++count;
  }

  return count;
}

void expire_items_single_map_iteratively(struct Vector *vector, struct Map *map,
                                         int start, int n_elems) {
  assert(start >= 0);
  assert(n_elems >= 0);
  void *key;
  for (int i = start; i < n_elems; i++) {
    vector_get(vector, i, (void **)&key);
    map_erase(map, key, (void **)&key);
  }
}

// Careful: SKETCH_HASHES needs to be <= SKETCH_SALTS_BANK_SIZE
#define SKETCH_HASHES 4
#define SKETCH_SALTS_BANK_SIZE 64

struct internal_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
};

static const uint32_t SKETCH_SALTS[SKETCH_SALTS_BANK_SIZE] = {
    0x9b78350f, 0x9bcf144c, 0x8ab29a3e, 0x34d48bf5, 0x78e47449, 0xd6e4af1d,
    0x32ed75e2, 0xb1eb5a08, 0x9cc7fbdf, 0x65b811ea, 0x41fd5ed9, 0x2e6a6782,
    0x3549661d, 0xbb211240, 0x78daa2ae, 0x8ce2d11f, 0x52911493, 0xc2497bd5,
    0x83c232dd, 0x3e413e9f, 0x8831d191, 0x6770ac67, 0xcd1c9141, 0xad35861a,
    0xb79cd83d, 0xce3ec91f, 0x360942d1, 0x905000fa, 0x28bb469a, 0xdb239a17,
    0x615cf3ae, 0xec9f7807, 0x271dcc3c, 0x47b98e44, 0x33ff4a71, 0x02a063f8,
    0xb051ebf2, 0x6f938d98, 0x2279abc3, 0xd55b01db, 0xaa99e301, 0x95d0587c,
    0xaee8684e, 0x24574971, 0x4b1e79a6, 0x4a646938, 0xa68d67f4, 0xb87839e6,
    0x8e3d388b, 0xed2af964, 0x541b83e3, 0xcb7fc8da, 0xe1140f8c, 0xe9724fd6,
    0x616a78fa, 0x610cd51c, 0x10f9173e, 0x8e180857, 0xa8f0b843, 0xd429a973,
    0xceee91e5, 0x1d4c6b18, 0x2a80e6df, 0x396f4d23,
};

struct Sketch {
  struct Map *clients;
  struct Vector *keys;
  struct Vector *buckets;
  struct DoubleChain *allocators[SKETCH_HASHES];

  uint32_t capacity;
  uint16_t threshold;

  map_key_hash *kh;
  struct internal_data internal;
};

struct hash {
  uint32_t value;
};

struct bucket {
  uint32_t value;
};

struct sketch_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
};

unsigned find_next_power_of_2_bigger_than(uint32_t d) {
  assert(d <= 0x80000000);
  unsigned n = 1;

  while (n < d) {
    n *= 2;
  }

  return n;
}

bool hash_eq(void *a, void *b) {
  struct hash *id1 = (struct hash *)a;
  struct hash *id2 = (struct hash *)b;

  return (id1->value == id2->value);
}

void hash_allocate(void *obj) {
  struct hash *id = (struct hash *)obj;
  id->value = 0;
}

unsigned hash_hash(void *obj) {
  struct hash *id = (struct hash *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->value);
  return hash;
}

int sketch_allocate(map_key_hash *kh, uint32_t capacity, uint16_t threshold,
                    struct Sketch **sketch_out) {
  assert(SKETCH_HASHES <= SKETCH_SALTS_BANK_SIZE);

  struct Sketch *sketch_alloc = (struct Sketch *)malloc(sizeof(struct Sketch));
  if (sketch_alloc == NULL) {
    return 0;
  }

  (*sketch_out) = sketch_alloc;

  (*sketch_out)->capacity = capacity;
  (*sketch_out)->threshold = threshold;
  (*sketch_out)->kh = kh;

  unsigned total_sketch_capacity =
      find_next_power_of_2_bigger_than(capacity * SKETCH_HASHES);

  (*sketch_out)->clients = NULL;
  if (map_allocate(hash_eq, hash_hash, total_sketch_capacity,
                   &((*sketch_out)->clients)) == 0) {
    return 0;
  }

  (*sketch_out)->keys = NULL;
  if (vector_allocate(sizeof(struct hash), total_sketch_capacity, hash_allocate,
                      &((*sketch_out)->keys)) == 0) {
    return 0;
  }

  (*sketch_out)->buckets = NULL;
  if (vector_allocate(sizeof(struct bucket), total_sketch_capacity, NULL,
                      &((*sketch_out)->buckets)) == 0) {
    return 0;
  }

  for (int i = 0; i < SKETCH_HASHES; i++) {
    (*sketch_out)->allocators[i] = NULL;
    if (dchain_allocate(capacity, &((*sketch_out)->allocators[i])) == 0) {
      return 0;
    }
  }

  return 1;
}

void sketch_compute_hashes(struct Sketch *sketch, void *key) {
  for (int i = 0; i < SKETCH_HASHES; i++) {
    sketch->internal.buckets_indexes[i] = -1;
    sketch->internal.present[i] = 0;
    sketch->internal.hashes[i] = 0;

    sketch->internal.hashes[i] =
        __builtin_ia32_crc32si(sketch->internal.hashes[i], SKETCH_SALTS[i]);
    sketch->internal.hashes[i] =
        __builtin_ia32_crc32si(sketch->internal.hashes[i], sketch->kh(key));
    sketch->internal.hashes[i] %= sketch->capacity;
  }
}

void sketch_refresh(struct Sketch *sketch, time_t now) {
  for (int i = 0; i < SKETCH_HASHES; i++) {
    map_get(sketch->clients, &sketch->internal.hashes[i],
            &sketch->internal.buckets_indexes[i]);
    dchain_rejuvenate_index(sketch->allocators[i],
                            sketch->internal.buckets_indexes[i], now);
  }
}

int sketch_fetch(struct Sketch *sketch) {
  int bucket_min_set = false;
  uint32_t *buckets_values[SKETCH_HASHES];
  uint32_t bucket_min = 0;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    sketch->internal.present[i] =
        map_get(sketch->clients, &sketch->internal.hashes[i],
                &sketch->internal.buckets_indexes[i]);

    if (!sketch->internal.present[i]) {
      continue;
    }

    int offseted = sketch->internal.buckets_indexes[i] + sketch->capacity * i;
    vector_get(sketch->buckets, offseted, (void **)&buckets_values[i]);

    if (!bucket_min_set || bucket_min > *buckets_values[i]) {
      bucket_min = *buckets_values[i];
      bucket_min_set = true;
    }
  }

  return bucket_min_set && bucket_min > sketch->threshold;
}

int sketch_touch_buckets(struct Sketch *sketch, time_t now) {
  for (int i = 0; i < SKETCH_HASHES; i++) {
    int bucket_index = -1;
    int present =
        map_get(sketch->clients, &sketch->internal.hashes[i], &bucket_index);

    if (!present) {
      int allocated_client =
          dchain_allocate_new_index(sketch->allocators[i], &bucket_index, now);

      if (!allocated_client) {
        // Sketch size limit reached.
        return false;
      }

      int offseted = bucket_index + sketch->capacity * i;

      uint32_t *saved_hash = 0;
      uint32_t *saved_bucket = 0;

      vector_get(sketch->keys, offseted, (void **)&saved_hash);
      vector_get(sketch->buckets, offseted, (void **)&saved_bucket);

      (*saved_hash) = sketch->internal.hashes[i];
      (*saved_bucket) = 0;
      map_put(sketch->clients, saved_hash, bucket_index);
    } else {
      dchain_rejuvenate_index(sketch->allocators[i], bucket_index, now);
      uint32_t *bucket;
      int offseted = bucket_index + sketch->capacity * i;
      vector_get(sketch->buckets, offseted, (void **)&bucket);
      (*bucket)++;
    }
  }

  return true;
}

void sketch_expire(struct Sketch *sketch, time_t time) {
  int offset = 0;
  int index = -1;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    offset = i * sketch->capacity;

    while (dchain_expire_one_index(sketch->allocators[i], &index, time)) {
      void *key;
      vector_get(sketch->keys, index + offset, &key);
      map_erase(sketch->clients, key, &key);
    }
  }
}

/**********************************************
 *
 *                  RTE-IP
 *
 **********************************************/

uint32_t __raw_cksum(const void *buf, size_t len, uint32_t sum) {
  /* workaround gcc strict-aliasing warning */
  uintptr_t ptr = (uintptr_t)buf;
  typedef uint16_t __attribute__((__may_alias__)) u16_p;
  const u16_p *u16_buf = (const u16_p *)ptr;

  while (len >= (sizeof(*u16_buf) * 4)) {
    sum += u16_buf[0];
    sum += u16_buf[1];
    sum += u16_buf[2];
    sum += u16_buf[3];
    len -= sizeof(*u16_buf) * 4;
    u16_buf += 4;
  }
  while (len >= sizeof(*u16_buf)) {
    sum += *u16_buf;
    len -= sizeof(*u16_buf);
    u16_buf += 1;
  }

  /* if length is in odd bytes */
  if (len == 1) {
    uint16_t left = 0;
    *(uint8_t *)&left = *(const uint8_t *)u16_buf;
    sum += left;
  }

  return sum;
}

uint16_t __raw_cksum_reduce(uint32_t sum) {
  sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
  sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
  return (uint16_t)sum;
}

uint16_t raw_cksum(const void *buf, size_t len) {
  uint32_t sum;

  sum = __raw_cksum(buf, len, 0);
  return __raw_cksum_reduce(sum);
}

uint16_t ipv4_cksum(const struct rte_ipv4_hdr *ipv4_hdr) {
  uint16_t cksum;
  cksum = raw_cksum(ipv4_hdr, sizeof(struct rte_ipv4_hdr));
  return (uint16_t)~cksum;
}

uint16_t ipv4_udptcp_cksum(const struct rte_ipv4_hdr *ipv4_hdr,
                           const void *l4_hdr) {
  uint32_t cksum;
  uint32_t l3_len, l4_len;

  l3_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
  if (l3_len < sizeof(struct rte_ipv4_hdr)) return 0;

  l4_len = l3_len - sizeof(struct rte_ipv4_hdr);

  cksum = raw_cksum(l4_hdr, l4_len);
  cksum += ipv4_cksum(ipv4_hdr);

  cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
  cksum = (~cksum) & 0xffff;
  /*
   * Per RFC 768:If the computed checksum is zero for UDP,
   * it is transmitted as all ones
   * (the equivalent in one's complement arithmetic).
   */
  if (cksum == 0 && ipv4_hdr->next_proto_id == IPPROTO_UDP) cksum = 0xffff;

  return (uint16_t)cksum;
}

/**********************************************
 *
 *                  ETHER
 *
 **********************************************/

bool rte_ether_addr_eq(void *a, void *b) {
  struct rte_ether_addr *id1 = (struct rte_ether_addr *)a;
  struct rte_ether_addr *id2 = (struct rte_ether_addr *)b;

  return (id1->addr_bytes[0] == id2->addr_bytes[0]) &&
         (id1->addr_bytes[1] == id2->addr_bytes[1]) &&
         (id1->addr_bytes[2] == id2->addr_bytes[2]) &&
         (id1->addr_bytes[3] == id2->addr_bytes[3]) &&
         (id1->addr_bytes[4] == id2->addr_bytes[4]) &&
         (id1->addr_bytes[5] == id2->addr_bytes[5]);
}

void rte_ether_addr_allocate(void *obj) {
  struct rte_ether_addr *id = (struct rte_ether_addr *)obj;

  id->addr_bytes[0] = 0;
  id->addr_bytes[1] = 0;
  id->addr_bytes[2] = 0;
  id->addr_bytes[3] = 0;
  id->addr_bytes[4] = 0;
  id->addr_bytes[5] = 0;
}

unsigned rte_ether_addr_hash(void *obj) {
  struct rte_ether_addr *id = (struct rte_ether_addr *)obj;

  uint8_t addr_bytes_0 = id->addr_bytes[0];
  uint8_t addr_bytes_1 = id->addr_bytes[1];
  uint8_t addr_bytes_2 = id->addr_bytes[2];
  uint8_t addr_bytes_3 = id->addr_bytes[3];
  uint8_t addr_bytes_4 = id->addr_bytes[4];
  uint8_t addr_bytes_5 = id->addr_bytes[5];

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, addr_bytes_0);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_1);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_2);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_3);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_4);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_5);
  return hash;
}

/**********************************************
 *
 *                  NF-RSS
 *
 **********************************************/

#define MBUF_CACHE_SIZE 256
#define RSS_HASH_KEY_LENGTH 52
#define MAX_NUM_DEVICES 32  // this is quite arbitrary...

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES];

struct lcore_conf {
  struct rte_mempool *mbuf_pool;
  uint16_t queue_id;
};

struct lcore_conf lcores_conf[RTE_MAX_LCORE];

/**********************************************
 *
 *                  NF-UTIL
 *
 **********************************************/

// rte_ether
struct rte_ether_addr;
struct rte_ether_hdr;

#define IP_MIN_SIZE_WORDS 5
#define WORD_SIZE 4

/**********************************************
 *
 *                  NF
 *
 **********************************************/

bool nf_init(void);
int nf_process(uint16_t device, uint8_t *buffer, uint16_t packet_length,
               time_t now);

// Unverified support for batching, useful for performance comparisons
#define BATCH_SIZE 32

// Do the opposite: we want batching!
static const uint16_t RX_QUEUE_SIZE = 1024;
static const uint16_t TX_QUEUE_SIZE = 1024;

// Buffer count for mempools
static const unsigned MEMPOOL_BUFFER_COUNT = 2048;

// Send the given packet to all devices except the packet's own
void flood(struct rte_mbuf *packet, uint16_t nb_devices, uint16_t queue_id) {
  rte_mbuf_refcnt_set(packet, nb_devices - 1);
  int total_sent = 0;
  uint16_t skip_device = packet->port;
  for (uint16_t device = 0; device < nb_devices; device++) {
    if (device != skip_device) {
      total_sent += rte_eth_tx_burst(device, queue_id, &packet, 1);
    }
  }
  // should not happen, but in case we couldn't transmit, ensure the packet is
  // freed
  if (total_sent != nb_devices - 1) {
    rte_mbuf_refcnt_set(packet, 1);
    rte_pktmbuf_free(packet);
  }
}

// Initializes the given device using the given memory pool
static int nf_init_device(uint16_t device, struct rte_mempool **mbuf_pools) {
  int retval;
  const uint16_t num_queues = rte_lcore_count();

  // device_conf passed to rte_eth_dev_configure cannot be NULL
  struct rte_eth_conf device_conf = {0};
  // device_conf.rxmode.hw_strip_crc = 1;
  device_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
  device_conf.rx_adv_conf.rss_conf = rss_conf[device];

  retval = rte_eth_dev_configure(device, num_queues, num_queues, &device_conf);
  if (retval != 0) {
    return retval;
  }

  // Allocate && set up TX queues
  for (int txq = 0; txq < num_queues; txq++) {
    retval = rte_eth_tx_queue_setup(device, txq, TX_QUEUE_SIZE,
                                    rte_eth_dev_socket_id(device), NULL);
    if (retval != 0) {
      return retval;
    }
  }

  unsigned lcore_id;
  int rxq = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    // Allocate && set up RX queues
    lcores_conf[lcore_id].queue_id = rxq;
    retval = rte_eth_rx_queue_setup(device, rxq, RX_QUEUE_SIZE,
                                    rte_eth_dev_socket_id(device), NULL,
                                    mbuf_pools[rxq]);
    if (retval != 0) {
      return retval;
    }

    rxq++;
  }

  // Start the device
  retval = rte_eth_dev_start(device);
  if (retval != 0) {
    return retval;
  }

  // Enable RX in promiscuous mode, just in case
  rte_eth_promiscuous_enable(device);
  if (rte_eth_promiscuous_get(device) != 1) {
    return retval;
  }

  return 0;
}

static void worker_main(void) {
  const unsigned lcore_id = rte_lcore_id();
  const uint16_t queue_id = lcores_conf[lcore_id].queue_id;

  if (!nf_init()) {
    rte_exit(EXIT_FAILURE, "Error initializing NF");
  }

  LOG("Core %u forwarding packets.", rte_lcore_id());

  if (rte_eth_dev_count_avail() != 2) {
    rte_exit(EXIT_FAILURE, "We assume there will be exactly 2 devices.");
  }

  while (1) {
    unsigned DEVICES_COUNT = rte_eth_dev_count_avail();

    for (uint16_t DEVICE = 0; DEVICE < DEVICES_COUNT; DEVICE++) {
      struct rte_mbuf *mbufs[BATCH_SIZE];
      uint16_t rx_count = rte_eth_rx_burst(DEVICE, queue_id, mbufs, BATCH_SIZE);

      struct rte_mbuf *mbufs_to_send[BATCH_SIZE];
      uint16_t tx_count = 0;

      for (uint16_t n = 0; n < rx_count; n++) {
        uint8_t *data = rte_pktmbuf_mtod(mbufs[n], uint8_t *);
        time_t NOW = current_time();
        uint16_t dst_device =
            nf_process(mbufs[n]->port, data, mbufs[n]->pkt_len, NOW);

        if (dst_device == DROP) {
          rte_pktmbuf_free(mbufs[n]);
        } else if (dst_device == FLOOD) {
          flood(mbufs[n], DEVICES_COUNT, queue_id);
        } else {
          mbufs_to_send[tx_count] = mbufs[n];
          tx_count++;
        }
      }

      uint16_t sent_count =
          rte_eth_tx_burst(1 - DEVICE, queue_id, mbufs_to_send, tx_count);
      for (uint16_t n = sent_count; n < tx_count; n++) {
        rte_pktmbuf_free(mbufs[n]);  // should not happen, but we're in the
                                     // unverified case anyway
      }
    }
  }
}

struct config_t {
  time_t expiration_time_us;
};

struct config_t config;

void app_parse_args(int argc, char **argv) {
  config.expiration_time_us = 0;

  if (argc <= 1) {
    rte_exit(EXIT_FAILURE, "Missing expiration time (us) as argument.\n");
  }

  char *temp;
  config.expiration_time_us = strtoul(argv[1], &temp, 10);

  // There's also a weird failure case with overflows, but let's not care
  if (temp == argv[1] || *temp != '\0') {
    rte_exit(EXIT_FAILURE, "Error while parsing expiration time: %s\n",
             argv[1]);
  }

  if (config.expiration_time_us == 0) {
    rte_exit(EXIT_FAILURE, "Expiration time must be strictly positive.\n");
  }
}

void report();

// Entry point
int main(int argc, char **argv) {
  signal(SIGINT, report);

  // Initialize the DPDK Environment Abstraction Layer (EAL)
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization, ret=%d\n", ret);
  }
  argc -= ret;
  argv += ret;

  app_parse_args(argc, argv);

  // Create a memory pool
  unsigned nb_devices = rte_eth_dev_count_avail();

  char MBUF_POOL_NAME[20];
  struct rte_mempool **mbuf_pools;
  mbuf_pools = (struct rte_mempool **)rte_malloc(
      NULL, sizeof(struct rte_mempool *) * rte_lcore_count(), 64);

  unsigned lcore_id;
  unsigned lcore_idx = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    sprintf(MBUF_POOL_NAME, "MEMORY_POOL_%u", lcore_idx);

    mbuf_pools[lcore_idx] =
        rte_pktmbuf_pool_create(MBUF_POOL_NAME,                     // name
                                MEMPOOL_BUFFER_COUNT * nb_devices,  // #elements
                                MBUF_CACHE_SIZE,  // cache size (per-lcore)
                                0,  // application private area size
                                RTE_MBUF_DEFAULT_BUF_SIZE,  // data buffer size
                                rte_socket_id()             // socket ID
        );

    if (mbuf_pools[lcore_idx] == NULL) {
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n",
               rte_strerror(rte_errno));
    }

    lcore_idx++;
  }

  // Initialize all devices
  for (uint16_t device = 0; device < nb_devices; device++) {
    ret = nf_init_device(device, mbuf_pools);
    if (ret == 0) {
      LOG("Initialized device %" PRIu16 ".", device);
    } else {
      rte_exit(EXIT_FAILURE, "Cannot init device %" PRIu16 ": %d", device, ret);
    }
  }

  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    rte_eal_remote_launch((lcore_function_t *)worker_main, NULL, lcore_id);
  }

  worker_main();

  return 0;
}

struct FlowId {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint8_t protocol;
};

void FlowId_allocate(void *obj) {
  struct FlowId *id = (struct FlowId *)obj;
  id->src_port = 0;
  id->dst_port = 0;
  id->src_ip = 0;
  id->dst_ip = 0;
  id->protocol = 0;
}

uint32_t FlowId_hash(void *obj) {
  struct FlowId *id = (struct FlowId *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->src_port);
  hash = __builtin_ia32_crc32si(hash, id->dst_port);
  hash = __builtin_ia32_crc32si(hash, id->src_ip);
  hash = __builtin_ia32_crc32si(hash, id->dst_ip);
  hash = __builtin_ia32_crc32si(hash, id->protocol);
  return hash;
}

bool FlowId_eq(void *a, void *b) {
  struct FlowId *id1 = (struct FlowId *)a;
  struct FlowId *id2 = (struct FlowId *)b;

  return (id1->src_port == id2->src_port) && (id1->dst_port == id2->dst_port) &&
         (id1->src_ip == id2->src_ip) && (id1->dst_ip == id2->dst_ip) &&
         (id1->protocol == id2->protocol);
}

struct tcpudp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
};

uint8_t hash_key_0[RSS_HASH_KEY_LENGTH] = {
    0xa1, 0x24, 0x0,  0x15, 0x0,  0x14, 0xa1, 0x24, 0xa1, 0x24, 0x0,
    0x14, 0xa1, 0x24, 0x0,  0x15, 0xa7, 0xfa, 0x11, 0x22, 0x6f, 0xd3,
    0xf0, 0x42, 0x1b, 0x6c, 0xeb, 0x14, 0x62, 0x2,  0xa3, 0x44, 0x24,
    0x90, 0xf8, 0x1c, 0x43, 0x99, 0xe7, 0xaf, 0x80, 0x73, 0x15, 0xfe,
    0x29, 0x5a, 0x73, 0xd0, 0x55, 0x85, 0xf2, 0xc4};
uint8_t hash_key_1[RSS_HASH_KEY_LENGTH] = {
    0x0,  0x14, 0xa1, 0x24, 0xa1, 0x24, 0x0,  0x15, 0x0,  0x14, 0xa1,
    0x24, 0x0,  0x14, 0xa1, 0x24, 0x6a, 0xe3, 0xac, 0x86, 0x3e, 0xcb,
    0x7e, 0x73, 0x83, 0x15, 0xcb, 0x75, 0xc4, 0x73, 0x2c, 0xda, 0xdb,
    0x5,  0x31, 0x46, 0xdb, 0xd4, 0x76, 0x5a, 0xa8, 0x20, 0x9d, 0xa,
    0x44, 0x7a, 0xc6, 0xae, 0x5d, 0x72, 0x34, 0x9c};

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES] = {
    {.rss_key = hash_key_0,
     .rss_key_len = RSS_HASH_KEY_LENGTH,
     .rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP},
    {.rss_key = hash_key_1,
     .rss_key_len = RSS_HASH_KEY_LENGTH,
     .rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP}};

struct churn_t {
  int64_t last_ts;
  uint64_t allocated_flows;
  uint64_t expired_flows;
};

static struct churn_t churns[RTE_MAX_LCORE];
static time_t start_time;

void churn_init(struct churn_t *churn) {
  churn->last_ts = current_time();
  churn->allocated_flows = 0;
  churn->expired_flows = 0;
}

RTE_DEFINE_PER_LCORE(struct Map *, _flows_map);
RTE_DEFINE_PER_LCORE(struct Vector *, _flows_values);
RTE_DEFINE_PER_LCORE(struct DoubleChain *, _flows_heap);
RTE_DEFINE_PER_LCORE(struct churn_t *, _churn);

void report() {
  time_t last_time = 0;
  uint64_t allocated_flows = 0;
  uint64_t expired_flows = 0;

  LOG("\n");
  LOG("*************************************");
  LOG("*                                   *");
  LOG("*      CHURN MEASUREMENT REPORT     *");
  LOG("*                                   *");
  LOG("*************************************");
  LOG();

  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    if (churns[lcore_id].last_ts > last_time) {
      last_time = churns[lcore_id].last_ts;
    }

    allocated_flows += churns[lcore_id].allocated_flows;
    expired_flows += churns[lcore_id].expired_flows;

    LOG("[%u] allocated %lu expired %lu", lcore_id,
        churns[lcore_id].allocated_flows, churns[lcore_id].expired_flows);
  }

  time_t delta_ns = last_time - start_time;
  double delta_min = ((double)delta_ns / (60.0 * 1e9));

  double allocated_fpm = allocated_flows / delta_min;
  double expired_fpm = expired_flows / delta_min;

  LOG();
  LOG("Elapsed time (s): %.1lf", delta_ns / 1e9);
  LOG("Allocated flows:  %lu (%.2lf fpm)", allocated_flows, allocated_fpm);
  LOG("Expired flows:    %lu (%.2lf fpm)", expired_flows, expired_fpm);

  exit(0);
}

bool nf_init() {
  unsigned lcore_id = rte_lcore_id();

  struct Map **flows_map = &RTE_PER_LCORE(_flows_map);
  struct Vector **flows_values = &RTE_PER_LCORE(_flows_values);
  struct DoubleChain **flows_heap = &RTE_PER_LCORE(_flows_heap);
  struct churn_t **churn = &RTE_PER_LCORE(_churn);

  if (!map_allocate(FlowId_eq, FlowId_hash, FLOW_CAPACITY, flows_map)) {
    return false;
  }

  if (!vector_allocate(sizeof(struct FlowId), FLOW_CAPACITY, FlowId_allocate,
                       flows_values)) {
    return false;
  }

  if (!dchain_allocate(FLOW_CAPACITY, flows_heap)) {
    return false;
  }

  if (lcore_id == rte_get_main_lcore()) {
    start_time = current_time();
  }

  (*churn) = &churns[lcore_id];
  churn_init(*churn);

  return true;
}

int nf_process(uint16_t device, uint8_t *packet, uint16_t packet_length,
               int64_t now) {
  struct Map *flows_map = RTE_PER_LCORE(_flows_map);
  struct Vector *flows_values = RTE_PER_LCORE(_flows_values);
  struct DoubleChain *flows_heap = RTE_PER_LCORE(_flows_heap);
  struct churn_t *churn = RTE_PER_LCORE(_churn);

  uint16_t dst_device = device ? 0 : 1;

  churn->last_ts = now;

  time_t last_time = now - config.expiration_time_us * 1000;  // us to ns
  int num_expired_flows =
      expire_items_single_map(flows_heap, flows_values, flows_map, last_time);

  churn->expired_flows += num_expired_flows;

  struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)(packet);

  packet += sizeof(struct rte_ether_hdr);
  packet_length -= sizeof(struct rte_ether_hdr);

  if ((rte_be_to_cpu_16(ether_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) ||
      (packet_length < sizeof(struct rte_ipv4_hdr))) {
    // drop
    LOG_DEBUG("[core=%u,dev=%u] Not IP (ethertype 0x%04x)", rte_lcore_id(),
              device, rte_be_to_cpu_16(ether_hdr->ether_type));
    return DROP;
  }

  struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)packet;
  packet += sizeof(struct rte_ipv4_hdr);
  packet_length -= sizeof(struct rte_ipv4_hdr);

  if (((ipv4_hdr->next_proto_id != IPPROTO_TCP) &&
       (ipv4_hdr->next_proto_id != IPPROTO_UDP)) ||
      (packet_length < sizeof(struct tcpudp_hdr))) {
    // drop
    LOG_DEBUG("[core=%u,dev=%u] Not TCP/UDP", rte_lcore_id(), device);
    return DROP;
  }

  struct tcpudp_hdr *tcpudp_hdr = (struct tcpudp_hdr *)packet;

  packet += sizeof(struct tcpudp_hdr);
  packet_length -= sizeof(struct tcpudp_hdr);

  struct FlowId flow = {
      .src_port = tcpudp_hdr->src_port,
      .dst_port = tcpudp_hdr->dst_port,
      .src_ip = ipv4_hdr->src_addr,
      .dst_ip = ipv4_hdr->dst_addr,
      .protocol = ipv4_hdr->next_proto_id,
  };

  int flow_index;
  int flow_found = map_get(flows_map, &flow, &flow_index);

  if (flow_found) {
    dchain_rejuvenate_index(flows_heap, flow_index, now);
    return dst_device;
  }

  int no_space = !dchain_allocate_new_index(flows_heap, &flow_index, now);

  if (no_space) {
    // drop
    LOG_DEBUG("[core=%u,dev=%u] No more space in dchain", rte_lcore_id(),
              device);
    return device;
  }

  LOG_DEBUG("[core=%u,dev=%u] Allocated new flow with index %u", rte_lcore_id(),
            device, flow_index);

  struct FlowId *key = 0;
  vector_get(flows_values, flow_index, (void **)&key);
  memcpy((void *)key, (void *)&flow, sizeof(struct FlowId));
  map_put(flows_map, key, flow_index);

  churn->allocated_flows++;

  return dst_device;
}
