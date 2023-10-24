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

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

/**
 * @brief Implementation of Oauth/OIDC token refresh callback function,
 *        will read a JWT token from disk, and forward it to the broker.
 */
void rd_kafka_file_token_refresh_cb(rd_kafka_t *rk,
                                    const char *oauthbearer_config,
                                    void *opaque) {
        if (rd_kafka_terminating(rk))
                return;
        
        char *jwt_token = NULL;

        struct stat st;

        int fd;
#ifndef _WIN32
        mode_t mode = 0644;
#else
        mode_t mode = _S_IREAD;
#endif

        if ((fd = rk->rk_conf.open_cb(rk->rk_conf.sasl.oauthbearer.token_file, O_RDONLY,
                                      mode, rk->rk_conf.opaque)) == -1) {
                rd_kafka_log(rk, LOG_ERR, "FILE",
                             "Failed to read OAUTHBEARER "
                             "token from \"%s\": %s",
                             rk->rk_conf.sasl.oauthbearer.token_file,
                             rd_strerror(errno));
                rd_kafka_oauthbearer_set_token_failure(rk, rd_strerror(errno));
                goto done;
        }

        if (fseek(fd, 0, SEEK_END) == -1) {
                rd_kafka_log(rk, LOG_ERR, "FILE",
                             "Failed to seek to end of OAUTHBEARER "
                             "token from \"%s\": %s",
                             rk->rk_conf.sasl.oauthbearer.token_file,
                             rd_strerror(errno));
                rd_kafka_oauthbearer_set_token_failure(rk, rd_strerror(errno));
                fclose(fd);
                goto done;
        }

        long fsize = ftell(fd);

        if (fseek(fd, 0, SEEK_SET) == -1) {
                rd_kafka_log(rk, LOG_ERR, "FILE",
                             "Failed to seek to start of OAUTHBEARER "
                             "token from \"%s\": %s",
                             rk->rk_conf.sasl.oauthbearer.token_file,
                             rd_strerror(errno));
                rd_kafka_oauthbearer_set_token_failure(rk, rd_strerror(errno));
                fclose(fd);
                goto done;
        }

        jwt_token = rd_malloc(fsize + 1);
        jwt_token[fsize] = '\0';

        if (fread(fd, jwt_token, 1, fsize) != fsize) {
                rd_kafka_log(rk, LOG_ERR, "FILE",
                             "Failed to read OAUTHBEARER "
                             "token from \"%s\": %s",
                             rk->rk_conf.sasl.oauthbearer.token_file,
                             rd_strerror(errno));
                rd_kafka_oauthbearer_set_token_failure(rk, rd_strerror(errno));
                fclose(fd);
                goto done;
        }
        fclose(fd);

        rd_kafka_jwt_refresh(rk, jwt_token);

done:
        RD_IF_FREE(jwt_token, rd_free);
}
