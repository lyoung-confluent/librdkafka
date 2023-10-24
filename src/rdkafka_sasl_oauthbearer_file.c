/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2021-2022, Magnus Edenhill
 *               2023, Confluent Inc.

 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


/**
 * Builtin SASL OAUTHBEARER file support
 */
#include "rdkafka_int.h"
#include "rdkafka_sasl_oauthbearer_jwt.h"
#include "rdunittest.h"

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

/**
 * @brief Reads a file from disk into a char buffer.
 */
int rd_kafka_file_read(char *buf, const char *filename) {
        FILE *f = fopen(filename, "r");
        if (f == NULL) {
                return errno;
        }
        if (fseek(f, 0L, SEEK_END) == -1) {
                fclose(f);
                return errno;
        }
        long fsize = ftell(f);
        if (fseek(f, 0L, SEEK_SET) == -1) {
                fclose(f);
                return errno;
        }
        buf = rd_malloc(fsize + 1);
        buf[fsize] = '\0';
        if (fread(f, buf, 1, fsize) != fsize) {
                fclose(f);
                return EIO;
        }
        return fclose(f);
}

/**
 * @brief Implementation of Oauth/OIDC token refresh callback function,
 *        will read a JWT token from disk, and forward it to the broker.
 */
void rd_kafka_file_token_refresh_cb(rd_kafka_t *rk,
                                    const char *oauthbearer_config,
                                    void *opaque) {
        if (rd_kafka_terminating(rk))
                return;
        
        int ferrno = 0;
        char *jwt_token = NULL;

        ferrno = rd_kafka_file_read(jwt_token, rk->rk_conf.sasl.oauthbearer.token_file);
        if (ferrno != 0) {
                rd_kafka_log(rk, LOG_ERR, "FILE",
                             "Failed to read OAUTHBEARER "
                             "token from \"%s\": %s",
                             rk->rk_conf.sasl.oauthbearer.token_file,
                             rd_strerror(ferrno));
                rd_kafka_oauthbearer_set_token_failure(rk, rd_strerror(ferrno));
                goto done;
        }

        rd_kafka_jwt_refresh(rk, jwt_token);

done:
        RD_IF_FREE(jwt_token, rd_free);
}


/**
 * @brief Make sure the jwt is able to be read from a file.
 */
static int unittest_sasl_oauthbearer_file(void) {
        /* Generate a token in the https://jwt.io/ website by using the
         * following steps:
         * 1. Select the algorithm RS256 from the Algorithm drop-down menu.
         * 2. Enter the header and the payload.
         *    payload should contains "exp", "iat", "sub", for example:
         *    payloads = {"exp": 1636532769,
                          "iat": 1516239022,
                          "sub": "sub"}
              header should contains "kid", for example:
              headers={"kid": "abcedfg"} */
        static const char *expected_jwt_token =
            "eyJhbGciOiJIUzI1NiIsInR5"
            "cCI6IkpXVCIsImtpZCI6ImFiY2VkZmcifQ"
            "."
            "eyJpYXQiOjE2MzIzNzUzMjAsInN1YiI6InN"
            "1YiIsImV4cCI6MTYzMjM3NTYyMH0"
            "."
            "bT5oY8K-rS2gQ7Awc40844bK3zhzBhZb7sputErqQHY";

        RD_UT_BEGIN();

        char *tmp_filename = tmpnam(NULL);

        FILE *fp;
        fp = fopen(tmp_filename, "w");
        RD_UT_ASSERT(fp != NULL, "Expected fopen to succeed");
        if (fwrite(expected_jwt_token, 1, 1, fp) != 1)
                RD_UT_FAIL("Failed to write to temporary file: %s", rd_strerror(errno));
        fclose(fp);

        char *actual_jwt_token;
        int ferrno = rd_kafka_file_read(actual_jwt_token, tmp_filename) ;
        RD_UT_ASSERT(ferrno == 0, "Expected rd_kafka_file_read to succeed: %s", rd_strerror(ferrno));

        RD_UT_ASSERT(!strcmp(expected_jwt_token, actual_jwt_token),
                     "Incorrect token received: "
                     "expected=%s; received=%s",
                     expected_jwt_token, actual_jwt_token);

        rd_free(tmp_filename);
        rd_free(actual_jwt_token);

        RD_UT_PASS();
}