/*
 *   Copyright 2015 Couchbase, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "couchbase_ext.h"

ID  cb_sym_positional;
ID  cb_sym_named;
ID  cb_sym_prepared;
ID  cb_sym_consistency;
int g_initialized = 0;

void init_n1ql();

static void
n1ql_callback(lcb_t handle, int type, const lcb_RESPN1QL *resp)
{
    struct cb_context_st *ctx = (struct cb_context_st *)resp->cookie;
    VALUE res = ctx->rv;
    if (resp->rflags & LCB_RESP_F_FINAL) {
        if (resp->rc != LCB_SUCCESS) {
            char buf[512];
            char *p = buf, *end = buf + 512;
            VALUE meta = Qnil;

            p += snprintf(buf, sizeof(buf), "failed to perform query, rc = 0x%02x", resp->rc);
            if (resp->htresp) {
                p += snprintf(p, end - p, ". Inner HTTP requeest failed (rc = 0x%02x, http_status = %d)",
                         resp->htresp->rc, resp->htresp->htstatus);
            }
            if (resp->row) {
                VALUE errors;
                meta = rb_funcall(cb_mMultiJson, cb_id_load, 1, STR_NEW(resp->row, resp->nrow));
                errors = rb_hash_lookup2(meta, STR_NEW_CSTR("errors"), Qnil);
                if (errors != Qnil) {
                    int i, len;
                    p += snprintf(p, end - p, ": ");
                    len = (int)RARRAY_LEN(errors);
                    for (i = 0; i < len; i++) {
                        VALUE error = rb_ary_entry(errors, i);
                        int code = FIX2INT(rb_hash_lookup2(error, STR_NEW_CSTR("code"), INT2FIX(0)));
                        char *msg = RSTRING_PTR(rb_hash_lookup2(error, STR_NEW_CSTR("msg"), STR_NEW_CSTR("")));
                        p += snprintf(p, end - p, "%s (%d)", msg, code);
                        if (len > 1 && i < len - 1) {
                            p += snprintf(p, end - p, ",");
                        }
                    }
                }
            }
            ctx->exception = rb_exc_new2(cb_eQuery, buf);
            rb_ivar_set(ctx->exception, cb_id_iv_error, INT2FIX(resp->rc));
            rb_ivar_set(ctx->exception, cb_id_iv_status, INT2FIX(resp->htresp->htstatus));
            rb_ivar_set(ctx->exception, cb_id_iv_meta, meta);
        }
        if (resp->row) {
            rb_hash_aset(res, cb_sym_meta, rb_funcall(cb_mMultiJson, cb_id_load, 1, STR_NEW(resp->row, resp->nrow)));
        }
    } else {
        /* TODO: protect from exceptions from MultiJson */
        VALUE rows = rb_hash_aref(res, cb_sym_rows);
        rb_ary_push(rows, rb_funcall(cb_mMultiJson, cb_id_load, 1, STR_NEW(resp->row, resp->nrow)));
    }
    (void)handle;
    (void)type;
}

typedef struct __cb_query_arg_i_TAG {
    lcb_N1QLPARAMS *params;
    lcb_CMDN1QL *cmd;
} __cb_query_arg_i;

static int
cb_query_extract_named_params_i(VALUE key, VALUE value, VALUE cookie)
{
    /* The callback for processing the value (sub-hash) of Named Parameterized Query Options main-hash.
     * Here key is the named argument defined in the query and the value is 
     * corresponding value.
     * This could be a multi-datatype hash based on the data type of the arguments.
     * It can also take hash value as a value which is then converted 
     * (MultiJson.dump(hash)) into JSON before setting them into lcb_n1p_namedparam.
     */
    lcb_error_t rc;
    __cb_query_arg_i *arg = (__cb_query_arg_i *)cookie;

    if (TYPE(key) == T_SYMBOL) {
        key = rb_sym2str(key);
    } else if (TYPE(key) != T_STRING) {
        lcb_n1p_free(arg->params);
        rb_raise(cb_eQuery, "expected key for N1QL query option to be a String or Symbol, given type: %d",
                (int)TYPE(key));
    }
    value = rb_funcall(cb_mMultiJson, cb_id_dump, 1, value);
    rc = lcb_n1p_namedparam(arg->params, RSTRING_PTR(key), RSTRING_LEN(key), RSTRING_PTR(value), RSTRING_LEN(value));
    if (rc != LCB_SUCCESS) {
        lcb_n1p_free(arg->params);
        rb_raise(cb_eQuery, "cannot set N1QL query named parameter: %.*s", (int)RSTRING_LEN(key),
                 RSTRING_PTR(key));
    }
    return ST_CONTINUE;
}

static int
cb_query_extract_params_i(VALUE key, VALUE value, VALUE cookie)
{
    lcb_error_t rc;
    __cb_query_arg_i *arg = (__cb_query_arg_i *)cookie;

    if (TYPE(key) == T_SYMBOL) {
        if (key == cb_sym_positional) {
            /* Processing the Positional Parameterized Query Options main-hash:
             * Here the key is :positional symbol and the value must be a sub-array that contains
             * the value of each positional argument defined in the query. 
             * This could be a multi-datatype array based on the data type of the arguments.
             * It can also take hash value as an element in the array which is then 
             * converted (MultiJson.dump(hash)) into JSON before setting them into lcb_n1p_posparam.
             */
            long ii;
            if (TYPE(value) != T_ARRAY) {
                lcb_n1p_free(arg->params);
                rb_raise(cb_eQuery,
                             "expected value of :positional option for N1QL query to be an Array, given type: %d",
                             (int)TYPE(value));
            }
            for (ii = 0; ii < RARRAY_LEN(value); ii++) {
                VALUE entry = rb_funcall(cb_mMultiJson, cb_id_dump, 1, rb_ary_entry(value, ii));
                rc = lcb_n1p_posparam(arg->params, RSTRING_PTR(entry), RSTRING_LEN(entry));
                if (rc != LCB_SUCCESS)
                    if (rc != LCB_SUCCESS) {
                        lcb_n1p_free(arg->params);
                        rb_raise(cb_eQuery, "cannot set N1QL query positional parameter");
                    }
            }
            return ST_CONTINUE;
        } else if (key == cb_sym_named) {
            /* Processing the Named Parameterized Query Options main-hash:
             * Here the key is :named symbol and the value must be a sub-hash that contains
             * the keys and values of each named argument defined in the query. 
             * The elements in the sub-hash are processed inside the Hash iteration callback.
             */
            if (TYPE(value) != T_HASH) {
                lcb_n1p_free(arg->params);
                rb_raise(cb_eQuery,
                             "expected value of :named option for N1QL query to be a Hash, given type: %d",
                             (int)TYPE(value));
            }
            rb_hash_foreach(value, cb_query_extract_named_params_i, (VALUE)arg);
            return ST_CONTINUE;
        } else if (key == cb_sym_prepared && RTEST(value)) {
            /* Enables the statement optimization at server side and generates a query plan.
             * The encoded query plan returned by the server will be cached by the SDK.
             * The cached plan will be used by SDK for the subsequent identical queries. 
             */
            int optimize = NUM2INT(value);
            if (optimize)
            {
                arg->cmd->cmdflags |= LCB_CMDN1QL_F_PREPCACHE;
            }
            return ST_CONTINUE; 
        } else if (key == cb_sym_consistency && RTEST(value)) {
            /* Added for passing the N1QL consistency mode to the couchbase.
             * Note: The consistency modes are defined in n1ql.h. Any invalid mode passed will be
             *       ignored and query effectively works like LCB_N1P_CONSISTENCY_NONE.
             */
            int consistency_mode = NUM2INT(value);
            rc = lcb_n1p_setconsistency(arg->params, consistency_mode);
            if (rc != LCB_SUCCESS)
            {
                lcb_n1p_free(arg->params);
                rb_raise(cb_eQuery, "Error setting Consistency mode[%d] in lcb_n1p_setconsistency. "
                        "Check for compatible consistency modes in n1ql.h: rc[%d]",
                        consistency_mode, rc);
            }
            return ST_CONTINUE;
        } else {
            key = rb_sym2str(key);
        }
    } else if (TYPE(key) != T_STRING) {
        lcb_n1p_free(arg->params);
        rb_raise(cb_eQuery, "expected key for N1QL query option to be a String or Symbol, given type: %d",
                     (int)TYPE(key));
    }
    /* Processing the Unknown symbol (hash key):
     * Any unknown symbol (key) and its value will be set in lcb_n1p_setopt().
     * If the value is a hash value, it will be converted (MultiJson.dump(hash)) into JSON 
     * before setting them into lcb_n1p_setopt.
     */
    value = rb_funcall(cb_mMultiJson, cb_id_dump, 1, value);
    rc = lcb_n1p_setopt(arg->params, RSTRING_PTR(key), RSTRING_LEN(key), RSTRING_PTR(value), RSTRING_LEN(value));
    if (rc != LCB_SUCCESS) {
        lcb_n1p_free(arg->params);
        rb_raise(cb_eQuery, "cannot set N1QL query option: %.*s", (int)RSTRING_LEN(key), RSTRING_PTR(key));
    }

    return ST_CONTINUE;
}

VALUE
cb_bucket_query(int argc, VALUE *argv, VALUE self)
{
    struct cb_bucket_st *bucket = DATA_PTR(self);
    struct cb_context_st *ctx;
    lcb_N1QLPARAMS *params = lcb_n1p_new();
    lcb_CMDN1QL cmd = { 0 };
    lcb_error_t rc;
    VALUE qstr, proc, args;
    VALUE exc, rv;
    VALUE options_hash = Qnil;

    init_n1ql();

    rb_scan_args(argc, argv, "11*&", &qstr, &options_hash, &args, &proc); 

    rc = lcb_n1p_setquery(params, RSTRING_PTR(qstr), RSTRING_LEN(qstr), LCB_N1P_QUERY_STATEMENT);
    if (rc != LCB_SUCCESS) {
        lcb_n1p_free(params);
        rb_raise(cb_eQuery, "cannot set query for N1QL command: %s", lcb_strerror(bucket->handle, rc));
    }

    /* The Options hash is an optional input param which could be passed as 
     * the second argument in query() method:
     * Ruby syntax: Bucket.query(queryString, optionsHash)
     * 
     * Forming the input data structure optionsHash in Ruby:
     *
     * Example 1: Positional Parameterized Query and N1QL timeout
     *      subArray = ["foo", "utopia"]
     *      optionsHash = {:positional=>subArray, :timeout=>"35000000us"}
     *      queryString = "select name, email from default where name == $1 and addr == $2"
     *      Bucket.query(queryString, optionsHash)
     *
     * Example 2: Named Parameterized Query, Prepared Statement and Consistency mode
     *      subHash = {"$nm"=>"foo", "$ad"=>"utopia"}
     *      optionsHash = {:named=>subHash, :consistency=>2, :prepared=>1}
     *      queryString = "select name, email from default where name == $nm and addr == $ad"
     *      Bucket.query(queryString, optionsHash)
     *      
     */
    if (options_hash != Qnil) {
        __cb_query_arg_i iarg = {0};
        if (TYPE(options_hash) != T_HASH) {
            lcb_n1p_free(params);
            rb_raise(cb_eQuery, "expected options to be a Hash, given type: %d", (int)TYPE(options_hash));
        }
        iarg.params = params;
        iarg.cmd = &cmd;
        rb_hash_foreach(options_hash, cb_query_extract_params_i, (VALUE)&iarg);
    }

    rc = lcb_n1p_mkcmd(params, &cmd);
    if (rc != LCB_SUCCESS) {
        lcb_n1p_free(params);
        rb_raise(cb_eQuery, "cannot construct N1QL command: %s", lcb_strerror(bucket->handle, rc));
    }

    ctx = cb_context_alloc_common(bucket, proc, 1);
    ctx->rv = rb_hash_new();
    rb_hash_aset(ctx->rv, cb_sym_rows, rb_ary_new());
    rb_hash_aset(ctx->rv, cb_sym_meta, Qnil);
    cmd.callback = n1ql_callback;
    rc = lcb_n1ql_query(bucket->handle, (void *)ctx, &cmd);
    if (rc != LCB_SUCCESS) {
        lcb_n1p_free(params);
        rb_raise(cb_eQuery, "cannot excute N1QL command: %s", lcb_strerror(bucket->handle, rc));
    }
    lcb_n1p_free(params);
    lcb_wait(bucket->handle);

    exc = ctx->exception;
    rv = ctx->rv;
    cb_context_free(ctx);
    if (exc != Qnil) {
        rb_exc_raise(exc);
    }
    exc = bucket->exception;
    if (exc != Qnil) {
        bucket->exception = Qnil;
        rb_exc_raise(exc);
    }
    return rv;
}

void
init_n1ql()
{
    if (!g_initialized)
    {
        g_initialized = 1;

        /* Below Ruby symbols are defined for the Options hash (an optional input). These symbols 
         * act as the key for the main-hash. The values are processed accordingly in the hash callbacks.
         * Any unknown symbol (key) and its value will be set in lcb_n1p_setopt().
         */
        cb_sym_positional = ID2SYM(rb_intern("positional"));
        cb_sym_named = ID2SYM(rb_intern("named"));
        cb_sym_prepared = ID2SYM(rb_intern("prepared"));
        cb_sym_consistency = ID2SYM(rb_intern("consistency"));
    }
}

