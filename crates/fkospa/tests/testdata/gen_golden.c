/*
 * gen_golden.c - Generate golden test vectors for Go cross-validation.
 *
 * This program uses libfko to create SPA packets with fixed inputs,
 * then prints the intermediate and final outputs for use as test fixtures.
 *
 * Build:
 *   gcc -I../../lib -L../../lib/.libs -o gen_golden gen_golden.c -lfko
 *
 * Run (from testdata dir):
 *   DYLD_LIBRARY_PATH=../../lib/.libs ./gen_golden > golden_vectors.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fko.h"

/* Print a labeled value */
static void emit(const char *label, const char *value) {
    printf("%s=%s\n", label, value ? value : "(null)");
}

static void emit_int(const char *label, int value) {
    printf("%s=%d\n", label, value);
}

/*
 * Generate one test vector with the given parameters.
 */
static int generate_vector(
    const char *test_name,
    const char *rand_val,
    const char *username,
    unsigned int timestamp,
    short msg_type,
    const char *access_msg,
    const char *nat_access,       /* NULL if not used */
    const char *server_auth,      /* NULL if not used */
    unsigned int client_timeout,
    short digest_type,
    int enc_mode,
    short hmac_type,
    const char *enc_key,
    const char *hmac_key          /* NULL to skip HMAC */
)
{
    fko_ctx_t ctx;
    int res;
    char *encoded_data = NULL;
    char *spa_data = NULL;

    printf("--- %s ---\n", test_name);

    /* Create context */
    res = fko_new(&ctx);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_new failed: %s\n", fko_errstr(res));
        return 1;
    }

    /* Set all fields to fixed values */
    res = fko_set_rand_value(ctx, rand_val);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_set_rand_value failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    res = fko_set_username(ctx, username);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_set_username failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    res = fko_set_timestamp(ctx, 0);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_set_timestamp failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    /* Override timestamp to exact value (fko_set_timestamp uses time(NULL)+offset).
     * We access the context internals directly since fko_set_timestamp
     * doesn't allow setting an absolute value through the public API.
     * Instead, we'll use the offset approach: set offset = desired - now.
     * But that's racy. Let's just use the API and record whatever we get.
     *
     * Actually, the timestamp field is just ctx->timestamp = time(NULL) + offset.
     * For golden vectors we need deterministic output, so let's record the
     * actual timestamp the C code produces and use that in Go tests.
     */

    /* For deterministic encoding tests, we need to know the exact timestamp.
     * Let's just record it.
     */

    res = fko_set_spa_message_type(ctx, msg_type);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_set_spa_message_type failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    res = fko_set_spa_message(ctx, access_msg);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_set_spa_message failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    if (nat_access != NULL) {
        res = fko_set_spa_nat_access(ctx, nat_access);
        if (res != FKO_SUCCESS) {
            fprintf(stderr, "fko_set_spa_nat_access failed: %s\n", fko_errstr(res));
            fko_destroy(ctx);
            return 1;
        }
    }

    if (server_auth != NULL) {
        res = fko_set_spa_server_auth(ctx, server_auth);
        if (res != FKO_SUCCESS) {
            fprintf(stderr, "fko_set_spa_server_auth failed: %s\n", fko_errstr(res));
            fko_destroy(ctx);
            return 1;
        }
    }

    if (client_timeout > 0) {
        res = fko_set_spa_client_timeout(ctx, client_timeout);
        if (res != FKO_SUCCESS) {
            fprintf(stderr, "fko_set_spa_client_timeout failed: %s\n", fko_errstr(res));
            fko_destroy(ctx);
            return 1;
        }
    }

    res = fko_set_spa_digest_type(ctx, digest_type);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_set_spa_digest_type failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    res = fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_RIJNDAEL);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_set_spa_encryption_type failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    res = fko_set_spa_encryption_mode(ctx, enc_mode);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_set_spa_encryption_mode failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    if (hmac_key != NULL) {
        res = fko_set_spa_hmac_type(ctx, hmac_type);
        if (res != FKO_SUCCESS) {
            fprintf(stderr, "fko_set_spa_hmac_type failed: %s\n", fko_errstr(res));
            fko_destroy(ctx);
            return 1;
        }
    }

    /* Encode (plaintext fields + digest, before encryption) */
    res = fko_encode_spa_data(ctx);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_encode_spa_data failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    res = fko_get_encoded_data(ctx, &encoded_data);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_get_encoded_data failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    /* Get the digest separately */
    char *digest = NULL;
    res = fko_get_spa_digest(ctx, &digest);

    /* Get the timestamp that was actually set */
    time_t ts;
    fko_get_timestamp(ctx, &ts);

    /* Emit the encoding results */
    emit("rand_val", rand_val);
    emit("username", username);
    emit_int("timestamp", (int)ts);
    emit("version", "3.0.0");
    emit_int("msg_type", msg_type);
    emit("access_msg", access_msg);
    if (nat_access) emit("nat_access", nat_access);
    if (server_auth) emit("server_auth", server_auth);
    if (client_timeout > 0) emit_int("client_timeout", client_timeout);
    emit_int("digest_type", digest_type);
    emit_int("enc_mode", enc_mode);
    if (hmac_key) emit_int("hmac_type", hmac_type);
    emit("enc_key", enc_key);
    if (hmac_key) emit("hmac_key", hmac_key);
    emit("encoded_data", encoded_data);
    if (digest) emit("digest", digest);

    /* Now encrypt and finalize */
    int enc_key_len = strlen(enc_key);
    int hmac_key_len = hmac_key ? strlen(hmac_key) : 0;

    res = fko_spa_data_final(ctx, enc_key, enc_key_len,
                             hmac_key, hmac_key_len);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_spa_data_final failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    res = fko_get_spa_data(ctx, &spa_data);
    if (res != FKO_SUCCESS) {
        fprintf(stderr, "fko_get_spa_data failed: %s\n", fko_errstr(res));
        fko_destroy(ctx);
        return 1;
    }

    emit("spa_data", spa_data);
    printf("\n");

    fko_destroy(ctx);
    return 0;
}

int main(void)
{
    int rc = 0;

    /* Test 1: Basic access message, SHA256, CBC, with HMAC */
    rc |= generate_vector(
        "basic_access_sha256_cbc_hmac",
        "1234567890123456",     /* rand_val */
        "testuser",             /* username */
        0,                      /* timestamp (will be overridden by current time) */
        FKO_ACCESS_MSG,         /* msg_type */
        "192.168.1.1,tcp/22",   /* access_msg */
        NULL,                   /* nat_access */
        NULL,                   /* server_auth */
        0,                      /* client_timeout */
        FKO_DIGEST_SHA256,      /* digest_type */
        FKO_ENC_MODE_CBC,       /* enc_mode */
        FKO_HMAC_SHA256,        /* hmac_type */
        "testkey123",           /* enc_key */
        "testhmacsecret"        /* hmac_key */
    );

    /* Test 2: Access with MD5 digest, no HMAC */
    rc |= generate_vector(
        "access_md5_cbc_nohmac",
        "9876543210987654",
        "admin",
        0,
        FKO_ACCESS_MSG,
        "10.0.0.1,tcp/443",
        NULL, NULL, 0,
        FKO_DIGEST_MD5,
        FKO_ENC_MODE_CBC,
        0,
        "md5testkey",
        NULL
    );

    /* Test 3: NAT access message */
    rc |= generate_vector(
        "nat_access_sha256",
        "5555666677778888",
        "natuser",
        0,
        FKO_NAT_ACCESS_MSG,
        "192.168.1.1,tcp/22",
        "10.0.0.100,22",
        NULL, 0,
        FKO_DIGEST_SHA256,
        FKO_ENC_MODE_CBC,
        FKO_HMAC_SHA256,
        "natkey",
        "nathmac"
    );

    /* Test 4: Access with client timeout */
    rc |= generate_vector(
        "access_timeout_sha256",
        "1111222233334444",
        "timeoutuser",
        0,
        FKO_ACCESS_MSG,
        "10.10.10.1,tcp/22",
        NULL, NULL,
        60,                     /* client_timeout */
        FKO_DIGEST_SHA256,
        FKO_ENC_MODE_CBC,
        FKO_HMAC_SHA256,
        "timeoutkey",
        "timeouthmac"
    );

    /* Test 5: SHA512 digest */
    rc |= generate_vector(
        "access_sha512",
        "4444333322221111",
        "sha512user",
        0,
        FKO_ACCESS_MSG,
        "172.16.0.1,udp/53",
        NULL, NULL, 0,
        FKO_DIGEST_SHA512,
        FKO_ENC_MODE_CBC,
        FKO_HMAC_SHA512,
        "sha512key",
        "sha512hmac"
    );

    /* Test 6: SHA1 digest */
    rc |= generate_vector(
        "access_sha1",
        "6666777788889999",
        "sha1user",
        0,
        FKO_ACCESS_MSG,
        "192.168.0.1,tcp/80",
        NULL, NULL, 0,
        FKO_DIGEST_SHA1,
        FKO_ENC_MODE_CBC,
        FKO_HMAC_SHA1,
        "sha1enckey",
        "sha1hmackey"
    );

    /* Test 7: Legacy IV mode */
    rc |= generate_vector(
        "access_legacy_iv",
        "7777888899990000",
        "legacyuser",
        0,
        FKO_ACCESS_MSG,
        "10.0.0.1,tcp/22",
        NULL, NULL, 0,
        FKO_DIGEST_SHA256,
        FKO_ENC_MODE_CBC_LEGACY_IV,
        FKO_HMAC_SHA256,
        "short",                /* short key to test legacy padding */
        "legacyhmac"
    );

    /* Test 8: With server auth */
    rc |= generate_vector(
        "access_with_server_auth",
        "1122334455667788",
        "authuser",
        0,
        FKO_ACCESS_MSG,
        "192.168.1.1,tcp/22",
        NULL,
        "my_server_auth",
        0,
        FKO_DIGEST_SHA256,
        FKO_ENC_MODE_CBC,
        FKO_HMAC_SHA256,
        "authkey",
        "authhmac"
    );

    return rc;
}
