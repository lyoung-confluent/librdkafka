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
 * Builtin SASL OAUTHBEARER support
 */
#include "rdkafka_int.h"
#include "rdkafka_sasl_int.h"
#include "rdunittest.h"
#include "cJSON.h"
#include "rdbase64.h"

/**
 * @brief The format of JWT is Header.Payload.Signature.
 *        Extract and decode payloads from JWT \p src.
 *        The decoded payloads will be returned in \p *bufplainp.
 *
 * @returns Return error message while decoding the payload.
 */
static const char *rd_kafka_jwt_b64_decode_payload(const char *src,
                                                   char **bufplainp) {
        char *converted_src;
        char *payload = NULL;

        const char *errstr = NULL;

        int i, padding, len;

        int payload_len;
        int nbytesdecoded;

        int payloads_start = 0;
        int payloads_end   = 0;

        len           = (int)strlen(src);
        converted_src = rd_malloc(len + 4);

        for (i = 0; i < len; i++) {
                switch (src[i]) {
                case '-':
                        converted_src[i] = '+';
                        break;

                case '_':
                        converted_src[i] = '/';
                        break;

                case '.':
                        if (payloads_start == 0)
                                payloads_start = i + 1;
                        else {
                                if (payloads_end > 0) {
                                        errstr =
                                            "The token is invalid with more "
                                            "than 2 delimiters";
                                        goto done;
                                }
                                payloads_end = i;
                        }
                        /* FALLTHRU */

                default:
                        converted_src[i] = src[i];
                }
        }

        if (payloads_start == 0 || payloads_end == 0) {
                errstr = "The token is invalid with less than 2 delimiters";
                goto done;
        }

        payload_len = payloads_end - payloads_start;
        payload     = rd_malloc(payload_len + 4);
        strncpy(payload, (converted_src + payloads_start), payload_len);

        padding = 4 - (payload_len % 4);
        if (padding < 4) {
                while (padding--)
                        payload[payload_len++] = '=';
        }

        nbytesdecoded = ((payload_len + 3) / 4) * 3;
        *bufplainp    = rd_malloc(nbytesdecoded + 1);

        if (EVP_DecodeBlock((uint8_t *)(*bufplainp), (uint8_t *)payload,
                            (int)payload_len) == -1) {
                errstr = "Failed to decode base64 payload";
        }

done:
        RD_IF_FREE(payload, rd_free);
        RD_IF_FREE(converted_src, rd_free);
        return errstr;
}

/**
 * @brief Partial Implementation of Oauth/OIDC token refresh callback
 *        function, extracts the provided jwt and forwards it to the broker.
 */
void rd_kafka_jwt_refresh(rd_kafka_t *rk, char *jwt_token) {

        double exp;

        cJSON *payloads = NULL;
        cJSON *jwt_exp, *jwt_sub;

        char *decoded_payloads = NULL;

        const char *sub;
        const char *errstr;

        size_t extension_cnt;
        size_t extension_key_value_cnt = 0;

        char set_token_errstr[512];
        char decode_payload_errstr[512];

        char **extensions          = NULL;
        char **extension_key_value = NULL;


        errstr = rd_kafka_jwt_b64_decode_payload(jwt_token, &decoded_payloads);
        if (errstr != NULL) {
                rd_snprintf(decode_payload_errstr,
                            sizeof(decode_payload_errstr),
                            "Failed to decode JWT payload: %s", errstr);
                rd_kafka_oauthbearer_set_token_failure(rk,
                                                       decode_payload_errstr);
                goto done;
        }

        payloads = cJSON_Parse(decoded_payloads);
        if (payloads == NULL) {
                rd_kafka_oauthbearer_set_token_failure(
                    rk, "Failed to parse JSON JWT payload");
                goto done;
        }

        jwt_exp = cJSON_GetObjectItem(payloads, "exp");
        if (jwt_exp == NULL) {
                rd_kafka_oauthbearer_set_token_failure(
                    rk,
                    "Expected JSON JWT response with "
                    "\"exp\" field");
                goto done;
        }

        exp = cJSON_GetNumberValue(jwt_exp);
        if (exp <= 0) {
                rd_kafka_oauthbearer_set_token_failure(
                    rk,
                    "Expected JSON JWT response with "
                    "valid \"exp\" field");
                goto done;
        }

        jwt_sub = cJSON_GetObjectItem(payloads, "sub");
        if (jwt_sub == NULL) {
                rd_kafka_oauthbearer_set_token_failure(
                    rk,
                    "Expected JSON JWT response with "
                    "\"sub\" field");
                goto done;
        }

        sub = cJSON_GetStringValue(jwt_sub);
        if (sub == NULL) {
                rd_kafka_oauthbearer_set_token_failure(
                    rk,
                    "Expected JSON JWT response with "
                    "valid \"sub\" field");
                goto done;
        }

        if (rk->rk_conf.sasl.oauthbearer.extensions_str) {
                extensions =
                    rd_string_split(rk->rk_conf.sasl.oauthbearer.extensions_str,
                                    ',', rd_true, &extension_cnt);

                extension_key_value = rd_kafka_conf_kv_split(
                    (const char **)extensions, extension_cnt,
                    &extension_key_value_cnt);
        }

        if (rd_kafka_oauthbearer_set_token(
                rk, jwt_token, (int64_t)exp * 1000, sub,
                (const char **)extension_key_value, extension_key_value_cnt,
                set_token_errstr,
                sizeof(set_token_errstr)) != RD_KAFKA_RESP_ERR_NO_ERROR)
                rd_kafka_oauthbearer_set_token_failure(rk, set_token_errstr);

done:
        RD_IF_FREE(decoded_payloads, rd_free);
        RD_IF_FREE(extensions, rd_free);
        RD_IF_FREE(extension_key_value, rd_free);
        RD_IF_FREE(payloads, cJSON_Delete);
}

