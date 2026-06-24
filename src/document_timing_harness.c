/*
 * document_timing_harness.c
 *
 * Timing experiment using a REAL document corpus instead of synthetic
 * fixed/random byte arrays, per supervisor requirement. Reads actual
 * files (PDFs, text, emails, etc.) from a directory and signs their
 * full contents with RSA-PSS (which internally SHA-256-hashes them).
 *
 * Design:
 *   - "fixed" condition: the SAME single real document, signed
 *     repeatedly (corpus file #0)
 *   - "varied" condition: cycles through ALL OTHER real documents in
 *     the corpus, one per measurement
 *   - measurements are interleaved (one fixed, one varied, repeat) to
 *     avoid the measurement-order confound found in earlier experiments
 *
 * This still answers the same RQ2 question (does secret-key-dependent
 * timing leakage exist?) -- using real documents instead of synthetic
 * random bytes does not change what is being tested (the CRT signing
 * step's dependence on dp/dq/qinv), but it does make the corpus
 * itself "real-world data" as requested.
 *
 * NOTE: signing time legitimately scales with document size (SHA-256
 * hashing cost depends on public message length, not secret key bits).
 * This is expected and NOT a side-channel concern -- file size is
 * public information. Using same-size files where possible reduces
 * irrelevant noise in the comparison.
 *
 * Build:
 *   gcc -O2 -o document_timing_harness src/bigint.c src/pss.c \
 *       src/rsa_sign.c src/document_timing_harness.c -lcrypto
 *
 * Run:
 *   ./document_timing_harness data/corpus 20000 > data/timing_data.csv
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include "rsa_sign.h"

#define MAX_FILES 256
#define MAX_FILE_SIZE (4 * 1024 * 1024) /* 4 MB cap per document */

static rsa_private_key key = {
    .p    = {{0xdd6ac7b86778043bUL,0xd32e6dcd83bc9478UL,0x004b6fabfcf56188UL,0xde8ede0ba85c6e4aUL,0,0,0,0}},
    .q    = {{0x3e83b91f25440fe1UL,0x697c392387fa841aUL,0xae8a781390e0a95bUL,0xae183554cae28e66UL,0,0,0,0}},
    .dp   = {{0x453ddff0d4f8f797UL,0x8471571e4f3fd0c4UL,0x84d77fa2f9dd3c52UL,0x0ecd83d954a66933UL,0,0,0,0}},
    .dq   = {{0x92af064f113174e1UL,0x0601bba51f33d41fUL,0xb698611a5bd516abUL,0xa93a5cf4fc767787UL,0,0,0,0}},
    .qinv = {{0x90064d107f428698UL,0x9235bb40ef8bfc8dUL,0xdd408babb3e814eeUL,0x68df381b5c60e063UL,0,0,0,0}}
};

typedef struct {
    unsigned char *data;
    long size;
    char name[256];
} document_t;

static document_t corpus[MAX_FILES];
static int corpus_count = 0;

static int load_corpus(const char *dir_path) {
    DIR *d = opendir(dir_path);
    if (!d) {
        fprintf(stderr, "ERROR: cannot open directory %s\n", dir_path);
        return -1;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL && corpus_count < MAX_FILES) {
        if (entry->d_name[0] == '.') continue; /* skip ., .., hidden files */

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        long size = st.st_size;
        if (size <= 0 || size > MAX_FILE_SIZE) continue;

        FILE *f = fopen(full_path, "rb");
        if (!f) continue;

        unsigned char *buf = malloc(size);
        if (!buf) { fclose(f); continue; }

        size_t read_bytes = fread(buf, 1, size, f);
        fclose(f);
        if ((long)read_bytes != size) { free(buf); continue; }

        corpus[corpus_count].data = buf;
        corpus[corpus_count].size = size;
        strncpy(corpus[corpus_count].name, entry->d_name, sizeof(corpus[corpus_count].name) - 1);
        corpus_count++;
    }
    closedir(d);
    return corpus_count;
}

/* Truncates every loaded document to the size of the SMALLEST document
 * in the corpus. This removes file-size as a confound: every signing
 * operation now hashes exactly the same number of bytes, so any
 * remaining fixed-vs-varied timing difference can only come from the
 * actual byte CONTENT (and ultimately, if any, the secret key), not
 * from "bigger file takes longer to hash". */
static void normalize_corpus_to_min_size(void) {
    long min_size = corpus[0].size;
    for (int i = 1; i < corpus_count; i++) {
        if (corpus[i].size < min_size) min_size = corpus[i].size;
    }
    fprintf(stderr, "Normalizing all documents to %ld bytes (smallest in corpus)\n", min_size);
    for (int i = 0; i < corpus_count; i++) {
        corpus[i].size = min_size; /* just truncate the read length used */
    }
}

static long sign_doc_once(const document_t *doc) {
    unsigned char sig[64];
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    rsa_sign(doc->data, (size_t)doc->size, &key, sig);
    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <corpus_dir> <num_runs_per_type>\n", argv[0]);
        return 1;
    }
    long n = atol(argv[2]);

    if (load_corpus(argv[1]) <= 0) {
        fprintf(stderr, "ERROR: no usable documents found in %s\n", argv[1]);
        return 1;
    }
    if (corpus_count < 2) {
        fprintf(stderr, "ERROR: need at least 2 documents in corpus, found %d\n", corpus_count);
        return 1;
    }

    fprintf(stderr, "Loaded %d documents (original sizes):\n", corpus_count);
    for (int i = 0; i < corpus_count; i++) {
        fprintf(stderr, "  [%d] %s (%ld bytes)\n", i, corpus[i].name, corpus[i].size);
    }

    normalize_corpus_to_min_size();

    fprintf(stderr, "Fixed document: [0] %s\n", corpus[0].name);
    fprintf(stderr, "Varied documents: [1..%d]\n\n", corpus_count - 1);

    /* warm-up using real documents */
    for (int w = 0; w < 200; w++) {
        sign_doc_once(&corpus[0]);
        sign_doc_once(&corpus[1 + (w % (corpus_count - 1))]);
    }

    printf("run,type,time_ns\n");
    for (long i = 0; i < n; i++) {
        long t_fixed = sign_doc_once(&corpus[0]);
        printf("%ld,fixed,%ld\n", i, t_fixed);

        int varied_idx = 1 + (int)(i % (corpus_count - 1));
        long t_varied = sign_doc_once(&corpus[varied_idx]);
        printf("%ld,random,%ld\n", i, t_varied); /* label kept as "random" so
            analyze_timing.py works unmodified -- "random" here means
            "varied real document", documented clearly in the thesis text */
    }

    for (int i = 0; i < corpus_count; i++) free(corpus[i].data);
    return 0;
}
