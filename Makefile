CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
LDFLAGS = -lcrypto

SRC_DIR = src
TEST_DIR = tests
SCRIPT_DIR = scripts

all: bigint_test mont_test modexp_test crt_test rsa_roundtrip_test baseline_test real_timing_harness benchmark_compare interleaved_timing_harness document_timing_harness

bigint_test: $(SRC_DIR)/bigint.c $(TEST_DIR)/test_bigint.c
	$(CC) $(CFLAGS) -o bigint_test $(SRC_DIR)/bigint.c $(TEST_DIR)/test_bigint.c $(LDFLAGS)

mont_test: $(SRC_DIR)/bigint.c $(TEST_DIR)/test_mont_mul.c
	$(CC) $(CFLAGS) -o mont_test $(SRC_DIR)/bigint.c $(TEST_DIR)/test_mont_mul.c $(LDFLAGS)

modexp_test: $(SRC_DIR)/bigint.c $(TEST_DIR)/test_modexp.c
	$(CC) $(CFLAGS) -o modexp_test $(SRC_DIR)/bigint.c $(TEST_DIR)/test_modexp.c $(LDFLAGS)

crt_test: $(SRC_DIR)/bigint.c $(TEST_DIR)/test_crt_sign.c
	$(CC) $(CFLAGS) -o crt_test $(SRC_DIR)/bigint.c $(TEST_DIR)/test_crt_sign.c $(LDFLAGS)

rsa_roundtrip_test: $(SRC_DIR)/bigint.c $(SRC_DIR)/pss.c $(SRC_DIR)/rsa_sign.c $(TEST_DIR)/test_rsa_roundtrip.c
	$(CC) $(CFLAGS) -o rsa_roundtrip_test $(SRC_DIR)/bigint.c $(SRC_DIR)/pss.c $(SRC_DIR)/rsa_sign.c $(TEST_DIR)/test_rsa_roundtrip.c $(LDFLAGS)

baseline_test: $(SRC_DIR)/bigint.c $(SRC_DIR)/baseline.c $(TEST_DIR)/test_baseline.c
	$(CC) $(CFLAGS) -o baseline_test $(SRC_DIR)/bigint.c $(SRC_DIR)/baseline.c $(TEST_DIR)/test_baseline.c $(LDFLAGS)

real_timing_harness: $(SRC_DIR)/bigint.c $(SRC_DIR)/real_timing_harness.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o real_timing_harness $(SRC_DIR)/bigint.c $(SRC_DIR)/real_timing_harness.c

benchmark_compare: $(SRC_DIR)/bigint.c $(SRC_DIR)/baseline.c $(SRC_DIR)/benchmark_compare.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o benchmark_compare $(SRC_DIR)/bigint.c $(SRC_DIR)/baseline.c $(SRC_DIR)/benchmark_compare.c

interleaved_timing_harness: $(SRC_DIR)/bigint.c $(SRC_DIR)/interleaved_timing_harness.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o interleaved_timing_harness $(SRC_DIR)/bigint.c $(SRC_DIR)/interleaved_timing_harness.c -lm

document_timing_harness: $(SRC_DIR)/bigint.c $(SRC_DIR)/pss.c $(SRC_DIR)/rsa_sign.c $(SRC_DIR)/document_timing_harness.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o document_timing_harness $(SRC_DIR)/bigint.c $(SRC_DIR)/pss.c $(SRC_DIR)/rsa_sign.c $(SRC_DIR)/document_timing_harness.c $(LDFLAGS)

clean:
	rm -f bigint_test mont_test modexp_test crt_test rsa_roundtrip_test baseline_test real_timing_harness benchmark_compare interleaved_timing_harness document_timing_harness timing_harness *.o

.PHONY: all clean