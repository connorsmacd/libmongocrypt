/*
 * Copyright 2023-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <mongocrypt-buffer-private.h>
#include <mongocrypt-config.h>
#include <mongocrypt-crypto-private.h>
#include <mongocrypt-opts-private.h>
#include <mongocrypt-private.h>

#include <test-mongocrypt.h>

#ifdef MONGOCRYPT_ENABLE_CRYPTO_LIBCRYPTO
#include <openssl/crypto.h>
#endif

#define BSON_STR(...) #__VA_ARGS__

static void test_mongocrypt_opts_kms_providers_lookup(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *bson = TEST_BSON(BSON_STR({"azure" : {"accessToken" : "bar"}}));

    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, bson), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    mc_kms_creds_t got;
    ASSERT(_mongocrypt_opts_kms_providers_lookup(&crypt->opts.kms_providers, "azure", &got));
    ASSERT(got.type == MONGOCRYPT_KMS_PROVIDER_AZURE);

    ASSERT(!_mongocrypt_opts_kms_providers_lookup(&crypt->opts.kms_providers, "local", &got));
    ASSERT(got.type == MONGOCRYPT_KMS_PROVIDER_NONE);

    mongocrypt_destroy(crypt);
}

/* Verify that _mongocrypt_secure_str_zero zeros every character of a
 * heap-allocated string while the memory is still live (no UB). */
static void test_secure_str_zero_clears_string(_mongocrypt_tester_t *tester) {
    const char *secret = "top-secret-credential";
    size_t len = strlen(secret);
    char *str = bson_strdup(secret);

    _mongocrypt_secure_str_zero(str);

    for (size_t i = 0; i < len; i++) {
        ASSERT(str[i] == 0x00);
    }
    bson_free(str);
}

/* Verify that _mongocrypt_secure_str_zero is NULL-safe. */
static void test_secure_str_zero_null_safe(_mongocrypt_tester_t *tester) {
    _mongocrypt_secure_str_zero(NULL); /* must not crash */
}

/* mongocrypt_setopt_use_secure_heap accepts non-zero sizes, accepts zero
 * (disabled, default), and rejects calls after init. */
static void test_setopt_use_secure_heap(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_use_secure_heap(crypt, 65536), crypt);
    mongocrypt_destroy(crypt);

    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_use_secure_heap(crypt, 0), crypt);
    mongocrypt_destroy(crypt);

    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, TEST_BSON(BSON_STR({"azure" : {"accessToken" : "bar"}}))), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    ASSERT_FAILS(mongocrypt_setopt_use_secure_heap(crypt, 65536), crypt, "options cannot be set after initialization");
    mongocrypt_destroy(crypt);
}

/* mongocrypt_secure_heap_min_size returns >= 4096 power-of-two values
 * scaled to the inputs. */
static void test_secure_heap_min_size(_mongocrypt_tester_t *tester) {
    size_t sz = mongocrypt_secure_heap_min_size(0, 0);
    ASSERT(sz >= 4096);
    ASSERT((sz & (sz - 1)) == 0);

    sz = mongocrypt_secure_heap_min_size(10, 3);
    /* raw = 10*320 + 3*2048 + 1024 = 10368; safe = 20736 -> next pow2 = 32768 */
    ASSERT(sz == 32768);

    /* power-of-two guarantee for larger values */
    sz = mongocrypt_secure_heap_min_size(256, 4);
    ASSERT((sz & (sz - 1)) == 0);
    ASSERT(sz >= 4096);
}

/* After mongocrypt_init with secure heap opt-in, OpenSSL's secure heap must be
 * initialized. This requires libcrypto. */
static void test_secure_heap_init_after_mongocrypt_init(_mongocrypt_tester_t *tester) {
#ifdef MONGOCRYPT_ENABLE_CRYPTO_LIBCRYPTO
    mongocrypt_t *const crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_use_secure_heap(crypt, 65536), crypt);
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, TEST_BSON(BSON_STR({"azure" : {"accessToken" : "bar"}}))), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    ASSERT(CRYPTO_secure_malloc_initialized());
    mongocrypt_destroy(crypt);
#endif
}

/* With secure heap opt-in, a DEK decrypted via _mongocrypt_unwrap_key lives on
 * the secure heap. */
static void test_unwrap_key_uses_secure_heap(_mongocrypt_tester_t *tester) {
#ifdef MONGOCRYPT_ENABLE_CRYPTO_LIBCRYPTO
    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_use_secure_heap(crypt, 65536), crypt);
    /* Local KMS provider with a fixed 96-byte test key. */
    /* 96 zero bytes base64-encoded = 128 'A' chars. */
    /* clang-format off */
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "subType" : "00"}}}}))), crypt);
    /* clang-format on */
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    /* Build a 96-byte DEK and wrap it with the local KEK. */
    _mongocrypt_buffer_t dek;
    _mongocrypt_buffer_init_size(&dek, MONGOCRYPT_KEY_LEN);
    memset(dek.data, 0x42, MONGOCRYPT_KEY_LEN);

    mc_kms_creds_t kc;
    ASSERT(_mongocrypt_opts_kms_providers_lookup(&crypt->opts.kms_providers, "local", &kc));

    _mongocrypt_buffer_t encrypted_dek;
    _mongocrypt_buffer_init(&encrypted_dek);
    ASSERT(_mongocrypt_wrap_key(crypt->crypto, &kc.value.local.key, &dek, &encrypted_dek, crypt->status));

    /* Unwrap and verify the result is on the secure heap. */
    _mongocrypt_buffer_t decrypted_dek;
    ASSERT(_mongocrypt_unwrap_key(crypt->crypto, &kc.value.local.key, &encrypted_dek, &decrypted_dek, crypt->status));
    ASSERT(CRYPTO_secure_allocated(decrypted_dek.data));
    ASSERT(decrypted_dek.len == MONGOCRYPT_KEY_LEN);
    ASSERT(0 == memcmp(decrypted_dek.data, dek.data, MONGOCRYPT_KEY_LEN));

    _mongocrypt_buffer_cleanup(&decrypted_dek);
    _mongocrypt_buffer_cleanup(&encrypted_dek);
    _mongocrypt_buffer_cleanup(&dek);
    mongocrypt_destroy(crypt);
#endif
}

/* With secure heap enabled, KMS credential strings parsed from setopt are
 * stored on the secure heap. */
static void test_kms_credentials_on_secure_heap(_mongocrypt_tester_t *tester) {
#ifdef MONGOCRYPT_ENABLE_CRYPTO_LIBCRYPTO
    mongocrypt_t *const crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_use_secure_heap(crypt, 65536), crypt);
    ASSERT_OK(mongocrypt_setopt_kms_providers(
                  crypt,
                  TEST_BSON(BSON_STR(
                      {"aws" : {"accessKeyId" : "my-access-key-id", "secretAccessKey" : "my-secret-access-key"}}))),
              crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    ASSERT(CRYPTO_secure_allocated(crypt->opts.kms_providers.aws_mut.access_key_id));
    ASSERT(CRYPTO_secure_allocated(crypt->opts.kms_providers.aws_mut.secret_access_key));
    mongocrypt_destroy(crypt);
#endif
}

void _mongocrypt_tester_install_opts(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mongocrypt_opts_kms_providers_lookup);
    INSTALL_TEST(test_secure_str_zero_clears_string);
    INSTALL_TEST(test_secure_str_zero_null_safe);
    INSTALL_TEST(test_setopt_use_secure_heap);
    INSTALL_TEST(test_secure_heap_min_size);
    INSTALL_TEST(test_secure_heap_init_after_mongocrypt_init);
    INSTALL_TEST(test_unwrap_key_uses_secure_heap);
    INSTALL_TEST(test_kms_credentials_on_secure_heap);
}
