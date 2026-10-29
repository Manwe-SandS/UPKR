/*
 * upkr-bk: UPKR packer for the BK-0010 unpackers, a self-contained C port of the
 * level 9 packer from https://github.com/exoticorn/upkr (Unlicense).
 *
 * The format is fixed: the same as
 *   upkr -r -9 --big-endian-bitstream --invert-is-match-bit
 *        --invert-continue-value-bit --invert-new-offset-bit
 * and the output is bit-identical to the Rust implementation.
 *
 * Build:  cc -O2 -o upkr-bk upkr-bk.c -lm
 * Usage:  upkr-bk <infile> [<outfile>]      pack (default outfile: <infile>.upk)
 *         upkr-bk -u <infile> [<outfile>]   unpack (default: <infile> without .upk)
 */
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* contexts */
#define NCTX (1 + 255 + 1 + 64 + 64)
#define CTX_NEW_OFFSET 256
#define CTX_OFFSET 257
#define CTX_LENGTH 321

/* level 9 parameters */
#define MAX_ARRIVALS 128
#define MAX_COST_DELTA 16.0
#define MAX_OFFSET_COST_DELTA 8.0
#define NUM_NEAR_MATCHES 8
#define GREEDY_SIZE 247
#define MAX_QUEUE_SIZE 900
#define PATIENCE 900
#define MAX_MATCHES_PER_LENGTH 9
#define MAX_LENGTH_DIFF 4

static void die(const char *msg)
{
    fprintf(stderr, "upkr-bk: %s\n", msg);
    exit(1);
}

static void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n ? n : 1);
    if (!p)
        die("out of memory");
    return p;
}

#define xmalloc(n) xrealloc(NULL, n)

static void reverse(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n / 2; i++) {
        uint8_t t = p[i];
        p[i] = p[n - 1 - i];
        p[n - 1 - i] = t;
    }
}

/* ---------- coder state (contexts) ---------- */

typedef struct {
    uint8_t ctx[NCTX];
    uint32_t last_offset;
    int prev_was_match;
} State;

static void state_init(State *s)
{
    memset(s->ctx, 128, sizeof s->ctx);
    s->last_offset = 0;
    s->prev_was_match = 0;
}

/* ---------- entropy coders: bit collector and cost counter ---------- */

typedef struct {
    int cost_mode;
    double cost;
    double log2t[256];
    uint16_t *bits;
    size_t n, cap;
} Coder;

static void coder_init(Coder *c, int cost_mode)
{
    memset(c, 0, sizeof *c);
    c->cost_mode = cost_mode;
    for (int p = 1; p < 256; p++)
        c->log2t[p] = log2(256.0 / (double)p);
}

static uint8_t adapt(unsigned prob, int bit)
{
    return bit ? prob + ((256 - prob + 8) >> 4) : prob - ((prob + 8) >> 4);
}

static void encode_bit(Coder *c, State *s, int idx, int bit)
{
    unsigned prob = s->ctx[idx];
    if (c->cost_mode) {
        c->cost += c->log2t[bit ? prob : 256 - prob];
    } else {
        if (c->n == c->cap) {
            c->cap = c->cap ? c->cap * 2 : 1024;
            c->bits = xrealloc(c->bits, c->cap * sizeof *c->bits);
        }
        c->bits[c->n++] = (uint16_t)(prob | ((unsigned)bit << 15));
    }
    s->ctx[idx] = adapt(prob, bit);
}

static void encode_length(Coder *c, State *s, int ctx, uint32_t value)
{
    while (value >= 2) {
        encode_bit(c, s, ctx, 0);
        encode_bit(c, s, ctx + 1, value & 1);
        ctx += 2;
        value >>= 1;
    }
    encode_bit(c, s, ctx, 1);
}

typedef struct {
    int is_literal;
    uint8_t lit;
    uint32_t offset, len;
} Op;

static void op_encode(const Op *op, Coder *c, State *s)
{
    if (op->is_literal) {
        encode_bit(c, s, 0, 1);
        int ci = 1;
        for (int i = 7; i >= 0; i--) {
            int bit = (op->lit >> i) & 1;
            encode_bit(c, s, ci, bit);
            ci = (ci << 1) | bit;
        }
        s->prev_was_match = 0;
    } else {
        encode_bit(c, s, 0, 0);
        int new_offset = 1;
        if (!s->prev_was_match) {
            new_offset = op->offset != s->last_offset;
            encode_bit(c, s, CTX_NEW_OFFSET, !new_offset);
        }
        if (new_offset) {
            encode_length(c, s, CTX_OFFSET, op->offset + 1);
            s->last_offset = op->offset;
        }
        encode_length(c, s, CTX_LENGTH, op->len);
        s->prev_was_match = 1;
    }
}

static void encode_eof(Coder *c, State *s)
{
    encode_bit(c, s, 0, 0);
    if (!s->prev_was_match)
        encode_bit(c, s, CTX_NEW_OFFSET, 0);
    encode_length(c, s, CTX_OFFSET, 1);
}

/* rANS bitstream (big endian) writer; returns the stream in decoding order */
static uint8_t *rans_finish(Coder *c, size_t *out_len)
{
    size_t cap = c->n / 2 + 64, n = 0;
    uint8_t *buf = xmalloc(cap);
    uint32_t state = 1u << 15;
    uint8_t byte = 0;
    int bit = 0;

#define PUT(b)                      \
    do {                            \
        if (n == cap)               \
            buf = xrealloc(buf, cap *= 2); \
        buf[n++] = (b);             \
    } while (0)
#define FLUSH()                                \
    do {                                       \
        byte |= (uint8_t)((state & 1) << bit); \
        if (++bit == 8) {                      \
            PUT(byte);                         \
            byte = bit = 0;                    \
        }                                      \
        state >>= 1;                           \
    } while (0)

    for (size_t k = c->n; k-- > 0;) {
        uint32_t step = c->bits[k];
        uint32_t prob = step & 32767, start;
        if (step & 32768) {
            start = 0;
        } else {
            start = prob;
            prob = 256 - prob;
        }
        uint32_t max_state = 256 * prob;
        while (state >= max_state)
            FLUSH();
        state = ((state / prob) << 8) + (state % prob) + start;
    }
    while (state > 0)
        FLUSH();
    if (byte != 0)
        PUT(byte);
    reverse(buf, n);
    *out_len = n;
    return buf;
#undef FLUSH
#undef PUT
}

/* ---------- suffix array, LCP and match finder ---------- */

typedef struct {
    size_t n;
    const uint8_t *data;
    int32_t *sa;
    uint32_t *rev;
    uint32_t *lcp;
    size_t *queue; /* binary max-heap */
    size_t qn;
} MatchFinder;

static int32_t *sa_rank, *sa_tmp_rank;
static size_t sa_n, sa_k;

static int sa_cmp(const void *pa, const void *pb)
{
    int32_t a = *(const int32_t *)pa, b = *(const int32_t *)pb;
    if (sa_rank[a] != sa_rank[b])
        return sa_rank[a] < sa_rank[b] ? -1 : 1;
    int32_t ra = (size_t)a + sa_k < sa_n ? sa_rank[a + sa_k] : -1;
    int32_t rb = (size_t)b + sa_k < sa_n ? sa_rank[b + sa_k] : -1;
    if (ra != rb)
        return ra < rb ? -1 : 1;
    return 0;
}

static void build_suffix_array(const uint8_t *data, size_t n, int32_t *sa)
{
    sa_n = n;
    sa_rank = xmalloc(n * sizeof *sa_rank);
    sa_tmp_rank = xmalloc(n * sizeof *sa_tmp_rank);
    for (size_t i = 0; i < n; i++) {
        sa[i] = (int32_t)i;
        sa_rank[i] = data[i];
    }
    for (sa_k = 1;; sa_k <<= 1) {
        qsort(sa, n, sizeof *sa, sa_cmp);
        if (n == 0)
            break;
        sa_tmp_rank[sa[0]] = 0;
        for (size_t i = 1; i < n; i++)
            sa_tmp_rank[sa[i]] = sa_tmp_rank[sa[i - 1]] + (sa_cmp(&sa[i - 1], &sa[i]) != 0);
        memcpy(sa_rank, sa_tmp_rank, n * sizeof *sa_rank);
        if ((size_t)sa_rank[sa[n - 1]] == n - 1)
            break;
    }
    free(sa_rank);
    free(sa_tmp_rank);
}

static void mf_init(MatchFinder *f, const uint8_t *data, size_t n)
{
    f->n = n;
    f->data = data;
    f->sa = xmalloc(n * sizeof *f->sa);
    f->rev = xmalloc(n * sizeof *f->rev);
    f->lcp = xmalloc(n * sizeof *f->lcp);
    f->queue = xmalloc((MAX_QUEUE_SIZE + 8) * sizeof *f->queue);
    f->qn = 0;
    build_suffix_array(data, n, f->sa);
    for (size_t i = 0; i < n; i++)
        f->rev[f->sa[i]] = (uint32_t)i;
    memset(f->lcp, 0, n * sizeof *f->lcp);
    size_t length = 0;
    for (size_t p = 0; p < n; p++) {
        size_t si = f->rev[p];
        if (si + 1 < n) {
            size_t i = (size_t)f->sa[si], j = (size_t)f->sa[si + 1];
            while (i + length < n && j + length < n && data[i + length] == data[j + length])
                length++;
            f->lcp[si] = (uint32_t)length;
        }
        length = length > 0 ? length - 1 : 0;
    }
}

static void heap_push(MatchFinder *f, size_t v)
{
    size_t i = f->qn++;
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (f->queue[parent] >= v)
            break;
        f->queue[i] = f->queue[parent];
        i = parent;
    }
    f->queue[i] = v;
}

static size_t heap_pop(MatchFinder *f)
{
    size_t top = f->queue[0];
    size_t v = f->queue[--f->qn];
    size_t i = 0;
    for (;;) {
        size_t c = 2 * i + 1;
        if (c >= f->qn)
            break;
        if (c + 1 < f->qn && f->queue[c + 1] > f->queue[c])
            c++;
        if (f->queue[c] <= v)
            break;
        f->queue[i] = f->queue[c];
        i = c;
    }
    if (f->qn > 0)
        f->queue[i] = v;
    return top;
}

typedef struct {
    size_t pos, length;
} Match;

typedef struct {
    Match *v;
    size_t n, cap;
} MatchVec;

typedef struct {
    MatchFinder *f;
    size_t pos_limit;
    size_t left_index, left_length, right_index, right_length;
    size_t current_length, matches_left, max_length;
} MatchIter;

static void it_move_left(MatchIter *it)
{
    MatchFinder *f = it->f;
    size_t patience = PATIENCE;
    while (it->left_length > 0 && patience > 0 && it->left_index > 0) {
        it->left_index--;
        size_t l = f->lcp[it->left_index];
        if (l < it->left_length)
            it->left_length = l;
        if ((size_t)f->sa[it->left_index] < it->pos_limit)
            return;
        patience--;
    }
    it->left_length = 0;
}

static void it_move_right(MatchIter *it)
{
    MatchFinder *f = it->f;
    size_t patience = PATIENCE;
    while (it->right_length > 0 && patience > 0 && it->right_index + 1 < f->n) {
        it->right_index++;
        size_t l = f->lcp[it->right_index - 1];
        if (l < it->right_length)
            it->right_length = l;
        if ((size_t)f->sa[it->right_index] < it->pos_limit)
            return;
        patience--;
    }
    it->right_length = 0;
}

static int it_next(MatchIter *it, Match *out)
{
    MatchFinder *f = it->f;
    if (f->qn == 0 || it->matches_left == 0) {
        f->qn = 0;
        size_t cl = it->current_length > 0 ? it->current_length - 1 : 0;
        size_t lr = it->left_length > it->right_length ? it->left_length : it->right_length;
        it->current_length = cl < lr ? cl : lr;
        if (it->current_length > it->max_length)
            it->max_length = it->current_length;
        if (it->current_length < 2 || it->current_length + MAX_LENGTH_DIFF < it->max_length)
            return 0;
        while (f->qn < MAX_QUEUE_SIZE &&
               (it->left_length == it->current_length || it->right_length == it->current_length)) {
            if (it->left_length == it->current_length) {
                heap_push(f, (size_t)f->sa[it->left_index]);
                it_move_left(it);
            }
            if (it->right_length == it->current_length) {
                heap_push(f, (size_t)f->sa[it->right_index]);
                it_move_right(it);
            }
        }
        it->matches_left = MAX_MATCHES_PER_LENGTH;
    }
    if (it->matches_left > 0)
        it->matches_left--;
    if (f->qn == 0)
        return 0;
    out->pos = heap_pop(f);
    out->length = it->current_length;
    return 1;
}

static void collect_matches(MatchFinder *f, size_t pos, MatchVec *out)
{
    MatchIter it;
    it.f = f;
    it.pos_limit = pos;
    f->qn = 0;
    size_t index = f->rev[pos];
    it.left_index = it.right_index = index;
    it.left_length = it.right_length = it.current_length = SIZE_MAX;
    it.matches_left = 0;
    it.max_length = 0;
    it_move_left(&it);
    it_move_right(&it);
    out->n = 0;
    Match m;
    while (it_next(&it, &m)) {
        if (out->n == out->cap) {
            out->cap = out->cap ? out->cap * 2 : 256;
            out->v = xrealloc(out->v, out->cap * sizeof *out->v);
        }
        out->v[out->n++] = m;
    }
}

/* ---------- optimal parser ---------- */

typedef struct Parse {
    struct Parse *prev;
    Op op;
    uint32_t refc;
} Parse;

typedef struct {
    Parse *parse;
    double cost;
    State st;
} Arrival;

typedef struct {
    Arrival **v;
    size_t n, cap;
} ArrVec;

static void parse_release(Parse *p)
{
    while (p && --p->refc == 0) {
        Parse *q = p->prev;
        free(p);
        p = q;
    }
}

static Parse *parse_new(Parse *prev, const Op *op)
{
    Parse *p = xmalloc(sizeof *p);
    p->prev = prev;
    if (prev)
        prev->refc++;
    p->op = *op;
    p->refc = 1;
    return p;
}

static void arrival_free(Arrival *a)
{
    parse_release(a->parse);
    free(a);
}

static void av_push(ArrVec *v, Arrival *a)
{
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->v = xrealloc(v->v, v->cap * sizeof *v->v);
    }
    v->v[v->n++] = a;
}

/* hash set of offsets seen while sorting */
#define HS_BITS 11
#define HS_SIZE (1u << HS_BITS)
static uint32_t hs_key[HS_SIZE], hs_stamp[HS_SIZE], hs_cur;

static int hs_insert(uint32_t k)
{
    uint32_t h = (k * 2654435761u) >> (32 - HS_BITS);
    for (;; h = (h + 1) & (HS_SIZE - 1)) {
        if (hs_stamp[h] != hs_cur) {
            hs_stamp[h] = hs_cur;
            hs_key[h] = k;
            return 1;
        }
        if (hs_key[h] == k)
            return 0;
    }
}

/* map offset -> best cost */
static uint32_t bo_key[HS_SIZE], bo_stamp[HS_SIZE], bo_cur;
static double bo_val[HS_SIZE];

static double *bo_slot(uint32_t k, int create)
{
    uint32_t h = (k * 2654435761u) >> (32 - HS_BITS);
    for (;; h = (h + 1) & (HS_SIZE - 1)) {
        if (bo_stamp[h] != bo_cur) {
            if (!create)
                return NULL;
            bo_stamp[h] = bo_cur;
            bo_key[h] = k;
            bo_val[h] = DBL_MAX;
            return &bo_val[h];
        }
        if (bo_key[h] == k)
            return &bo_val[h];
    }
}

static void merge_sort_arrivals(Arrival **v, Arrival **tmp, size_t n)
{
    for (size_t w = 1; w < n; w *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * w) {
            size_t mid = lo + w < n ? lo + w : n;
            size_t hi = lo + 2 * w < n ? lo + 2 * w : n;
            size_t i = lo, j = mid, k = lo;
            while (i < mid && j < hi)
                tmp[k++] = (v[j]->cost < v[i]->cost) ? v[j++] : v[i++];
            while (i < mid)
                tmp[k++] = v[i++];
            while (j < hi)
                tmp[k++] = v[j++];
        }
        memcpy(v, tmp, n * sizeof *v);
    }
}

static void sort_arrivals(ArrVec *vec)
{
    size_t n = vec->n;
    if (n == 0)
        return;
    Arrival **tmp = xmalloc(n * sizeof *tmp);
    Arrival **remaining = xmalloc(n * sizeof *remaining);
    size_t nrem = 0;
    merge_sort_arrivals(vec->v, tmp, n);
    Arrival **sorted = tmp;
    memcpy(sorted, vec->v, n * sizeof *sorted);
    vec->n = 0;
    hs_cur++;
    for (size_t i = 0; i < n; i++) {
        Arrival *a = sorted[i];
        if (hs_insert(a->st.last_offset)) {
            if (vec->n < MAX_ARRIVALS)
                vec->v[vec->n++] = a;
            else
                arrival_free(a);
        } else {
            remaining[nrem++] = a;
        }
    }
    for (size_t i = 0; i < nrem; i++) {
        if (vec->n >= MAX_ARRIVALS) {
            for (; i < nrem; i++)
                arrival_free(remaining[i]);
            break;
        }
        vec->v[vec->n++] = remaining[i];
    }
    free(tmp);
    free(remaining);
}

static void add_arrival(ArrVec *arrivals, size_t pos, Arrival *a)
{
    ArrVec *vec = &arrivals[pos];
    av_push(vec, a);
    if (vec->n > MAX_ARRIVALS * 2)
        sort_arrivals(vec);
}

static void add_op(ArrVec *arrivals, Coder *cc, size_t to, const Op *op, const Arrival *arrival)
{
    Arrival *a = xmalloc(sizeof *a);
    a->st = arrival->st;
    cc->cost = 0.0;
    op_encode(op, cc, &a->st);
    a->parse = parse_new(arrival->parse, op);
    a->cost = arrival->cost + cc->cost;
    add_arrival(arrivals, to, a);
}

static size_t match_length(const uint8_t *data, size_t n, size_t pos, size_t offset)
{
    size_t length = 0;
    while (pos + length < n && data[pos + length] == data[pos - offset + length])
        length++;
    return length;
}

static void add_match(ArrVec *arrivals, Coder *cc, size_t pos, size_t offset, size_t length,
                      const Arrival *arrival)
{
    Op op = {0, 0, (uint32_t)offset, (uint32_t)length};
    if (length >= 1)
        add_op(arrivals, cc, pos + length, &op, arrival);
}

static Parse *parse_data(const uint8_t *data, size_t n)
{
    MatchFinder mf;
    mf_init(&mf, data, n);
    size_t near_matches[1024];
    size_t last_seen[256];
    memset(near_matches, 0xff, sizeof near_matches);
    memset(last_seen, 0xff, sizeof last_seen);

    ArrVec *arrivals = xmalloc((n + 1) * sizeof *arrivals);
    memset(arrivals, 0, (n + 1) * sizeof *arrivals);
    Coder cc;
    coder_init(&cc, 1);
    MatchVec mv = {0, 0, 0};

    Arrival *first = xmalloc(sizeof *first);
    first->parse = NULL;
    first->cost = 0.0;
    state_init(&first->st);
    add_arrival(arrivals, 0, first);

    for (size_t pos = 0; pos < n; pos++) {
        ArrVec here = arrivals[pos];
        memset(&arrivals[pos], 0, sizeof arrivals[pos]);
        if (here.n == 0) {
            free(here.v);
            continue;
        }
        sort_arrivals(&here);

        bo_cur++;
        double best_cost = DBL_MAX;
        for (size_t i = 0; i < here.n; i++) {
            Arrival *a = here.v[i];
            if (a->cost < best_cost)
                best_cost = a->cost;
            double *slot = bo_slot(a->st.last_offset, 1);
            if (a->cost < *slot)
                *slot = a->cost;
        }

        int matches_ready = 0;
        size_t i;
        for (i = 0; i < here.n; i++) {
            Arrival *arrival = here.v[i];
            double lim1 = best_cost + MAX_COST_DELTA;
            double lim2 = *bo_slot(arrival->st.last_offset, 0) + MAX_OFFSET_COST_DELTA;
            if (arrival->cost > (lim1 < lim2 ? lim1 : lim2))
                continue;

            if (!matches_ready) {
                collect_matches(&mf, pos, &mv);
                matches_ready = 1;
            }
            int found_last_offset = 0;
            int have_closest = 0;
            size_t closest_match = 0;
            int greedy_break = 0;
            for (size_t k = 0; k < mv.n; k++) {
                Match m = mv.v[k];
                if (!have_closest || m.pos > closest_match)
                    closest_match = m.pos;
                have_closest = 1;
                size_t offset = pos - m.pos;
                found_last_offset |= offset == arrival->st.last_offset;
                add_match(arrivals, &cc, pos, offset, m.length, arrival);
                if (m.length >= GREEDY_SIZE) {
                    greedy_break = 1;
                    break;
                }
            }
            if (greedy_break)
                break;

            size_t near_left = NUM_NEAR_MATCHES;
            size_t match_pos = last_seen[data[pos]];
            while (near_left > 0 && match_pos != SIZE_MAX &&
                   (!have_closest || closest_match < match_pos)) {
                size_t offset = pos - match_pos;
                add_match(arrivals, &cc, pos, offset, match_length(data, n, pos, offset), arrival);
                found_last_offset |= offset == arrival->st.last_offset;
                if (offset < 1024)
                    match_pos = near_matches[match_pos % 1024];
                near_left--;
            }

            if (!found_last_offset && arrival->st.last_offset > 0) {
                size_t offset = arrival->st.last_offset;
                add_match(arrivals, &cc, pos, offset, match_length(data, n, pos, offset), arrival);
            }

            Op op = {1, data[pos], 0, 0};
            add_op(arrivals, &cc, pos + 1, &op, arrival);
        }
        for (size_t k = 0; k < here.n; k++)
            arrival_free(here.v[k]);
        free(here.v);

        near_matches[pos % 1024] = last_seen[data[pos]];
        last_seen[data[pos]] = pos;
    }

    Parse *result = arrivals[n].v[0]->parse;
    if (result)
        result->refc++;
    for (size_t k = 0; k < arrivals[n].n; k++)
        arrival_free(arrivals[n].v[k]);
    free(arrivals[n].v);
    free(arrivals);
    free(mv.v);
    free(mf.sa);
    free(mf.rev);
    free(mf.lcp);
    free(mf.queue);
    return result;
}

static uint8_t *pack(const uint8_t *data, size_t n, size_t *out_len)
{
    Parse *parse = parse_data(data, n);
    size_t nops = 0;
    for (Parse *p = parse; p; p = p->prev)
        nops++;
    Op *ops = xmalloc(nops * sizeof *ops);
    size_t k = nops;
    for (Parse *p = parse; p; p = p->prev)
        ops[--k] = p->op;
    parse_release(parse);

    State st;
    state_init(&st);
    Coder coder;
    coder_init(&coder, 0);
    for (size_t i = 0; i < nops; i++)
        op_encode(&ops[i], &coder, &st);
    encode_eof(&coder, &st);
    uint8_t *packed = rans_finish(&coder, out_len);
    free(coder.bits);
    free(ops);
    return packed;
}

/* ---------- unpacker ---------- */

typedef struct {
    const uint8_t *data;
    size_t len, pos;
    uint32_t state;
    uint8_t byte;
    int bits_left;
    int eof;
} Decoder;

static int dec_bit(Decoder *d, State *s, int idx)
{
    while (d->state < 32768) {
        if (d->bits_left == 0) {
            if (d->pos >= d->len) {
                d->eof = 1;
                return 0;
            }
            d->byte = d->data[d->pos++];
            d->bits_left = 8;
        }
        d->state = (d->state << 1) | (d->byte >> 7);
        d->byte <<= 1;
        d->bits_left--;
    }
    unsigned prob = s->ctx[idx];
    int bit = (d->state & 255) < prob;
    unsigned start = 0, p = prob;
    if (!bit) {
        start = prob;
        p = 256 - prob;
    }
    d->state = p * (d->state >> 8) + (d->state & 255) - start;
    s->ctx[idx] = adapt(prob, bit);
    return bit;
}

/* Elias-gamma style number with interleaved context bits */
static uint32_t dec_number(Decoder *d, State *s, int ci)
{
    uint32_t v = 0;
    int pos = 0;
    while (dec_bit(d, s, ci) == 0) {
        if (d->eof || pos >= 31)
            die("corrupt data");
        v |= (uint32_t)dec_bit(d, s, ci + 1) << pos++;
        ci += 2;
    }
    return v | 1u << pos;
}

static uint8_t *unpack(const uint8_t *data, size_t len, size_t *out_len)
{
    Decoder d = {data, len, 0, 0, 0, 0, 0};
    State s;
    state_init(&s);
    size_t cap = 65536, n = 0;
    uint8_t *out = xmalloc(cap);
    size_t offset = 0;
    int prev_was_match = 0;
    for (;;) {
        if (dec_bit(&d, &s, 0) == 0) { /* match */
            if (prev_was_match || dec_bit(&d, &s, CTX_NEW_OFFSET) == 0) {
                offset = dec_number(&d, &s, CTX_OFFSET) - 1;
                if (offset == 0)
                    break;
            }
            uint32_t length = dec_number(&d, &s, CTX_LENGTH);
            if (offset > n)
                die("match offset out of range");
            while (n + length > cap) {
                cap *= 2;
                out = xrealloc(out, cap);
            }
            for (uint32_t i = 0; i < length; i++, n++)
                out[n] = out[n - offset];
            prev_was_match = 1;
        } else {
            int ci = 1;
            for (int i = 0; i < 8; i++)
                ci = (ci << 1) | dec_bit(&d, &s, ci);
            if (n == cap) {
                cap *= 2;
                out = xrealloc(out, cap);
            }
            out[n++] = (uint8_t)ci;
            prev_was_match = 0;
        }
        if (d.eof)
            die("unexpected end of input");
    }
    *out_len = n;
    return out;
}

/* ---------- command line ---------- */

static void usage(void)
{
    fprintf(stderr,
            "Usage:\n"
            "  upkr-bk <infile> [<outfile>]      pack (default outfile: <infile>.upk)\n"
            "  upkr-bk -u <infile> [<outfile>]   unpack (default outfile: <infile> without .upk)\n"
            "\n"
            "Fixed format for the BK-0010 unpackers: reversed, level 9, big-endian bitstream,\n"
            "inverted is-match / new-offset / continue-value bits.\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int do_unpack = 0;
    const char *files[2];
    int nfiles = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "-d"))
            do_unpack = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
            usage();
        else if (argv[i][0] == '-' && argv[i][1])
            die("unknown option");
        else if (nfiles < 2)
            files[nfiles++] = argv[i];
        else
            usage();
    }
    if (nfiles == 0)
        usage();

    FILE *f = fopen(files[0], "rb");
    if (!f)
        die("cannot open input file");
    size_t cap = 65536, n = 0;
    uint8_t *data = xmalloc(cap);
    size_t got;
    while ((got = fread(data + n, 1, cap - n, f)) > 0) {
        n += got;
        if (n == cap) {
            cap *= 2;
            data = xrealloc(data, cap);
        }
    }
    fclose(f);
    /* the BK unpackers read the .bin header from the end of the unpacked data
       as words, so the data must have an even size: pad an odd input with a
       zero byte at the end (the .bin length field makes the copy ignore it) */
    if (!do_unpack && (n & 1)) {
        if (n == cap)
            data = xrealloc(data, cap + 1);
        data[n++] = 0;
    }
    reverse(data, n);

    uint8_t *result;
    size_t rlen;
    char outname[4096];
    if (do_unpack) {
        result = unpack(data, n, &rlen);
        size_t l = strlen(files[0]);
        if (l > 4 && !strcmp(files[0] + l - 4, ".upk"))
            snprintf(outname, sizeof outname, "%.*s", (int)(l - 4), files[0]);
        else
            snprintf(outname, sizeof outname, "%s.bin", files[0]);
    } else {
        result = pack(data, n, &rlen);
        fprintf(stderr, "Compressed %zu bytes to %zu bytes (%.2f%%)\n", n, rlen,
                n ? rlen * 100.0 / n : 0.0);
        snprintf(outname, sizeof outname, "%s.upk", files[0]);
    }
    reverse(result, rlen);
    if (nfiles == 2)
        snprintf(outname, sizeof outname, "%s", files[1]);
    f = fopen(outname, "wb");
    if (!f)
        die("cannot create output file");
    /* the BK unpackers need an even address and size.
       Pad an odd result with a zero byte at the front
       (the unpacker reads the data from the end and never gets that far) */
    if (!do_unpack && (rlen & 1) && fputc(0, f) == EOF)
        die("write error");
    if (fwrite(result, 1, rlen, f) != rlen)
        die("write error");
    fclose(f);
    free(result);
    free(data);
    return 0;
}
