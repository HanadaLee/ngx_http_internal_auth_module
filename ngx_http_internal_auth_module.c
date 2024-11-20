
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


typedef struct {
    ngx_str_t      result;
} ngx_http_internal_auth_ctx_t;


typedef struct {
    ngx_flag_t     enable;
    ngx_array_t   *request_secrets;
    ngx_str_t      proxy_secret;
    ngx_flag_t     empty_deny;
    ngx_flag_t     failure_deny;
    time_t         timeout;
    ngx_str_t      header_name;
} ngx_http_internal_auth_conf_t;


static ngx_int_t ngx_http_internal_auth_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_internal_auth_result_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_internal_auth_proxy_fingerprint_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
char *ngx_http_internal_auth_set_request_secrets_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_str_t ngx_http_internal_auth_compute_md5_hex(
    ngx_http_request_t *r, const u_char *data, size_t len);
static ngx_table_elt_t* ngx_http_internal_auth_get_header(
    ngx_http_request_t *r, ngx_str_t *name);
static ngx_int_t ngx_http_internal_auth_deny(ngx_http_request_t *r,
    ngx_http_internal_auth_ctx_t *ctx, const char *log_message,
    ngx_uint_t deny_flag);
static ngx_int_t ngx_http_internal_auth_handler(ngx_http_request_t *r);
static void *ngx_http_internal_auth_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_internal_auth_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_internal_auth_init(ngx_conf_t *cf);


static ngx_command_t ngx_http_internal_auth_commands[] = {
    { ngx_string("internal_auth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, enable),
      NULL },
      
    { ngx_string("internal_auth_request_secrets"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1234,
      ngx_http_internal_auth_set_request_secrets_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, request_secrets),
      NULL },

    { ngx_string("internal_auth_proxy_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, proxy_secret),
      NULL },

    { ngx_string("internal_auth_empty_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, empty_deny),
      NULL },
      
    { ngx_string("internal_auth_failure_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, failure_deny),
      NULL },
      
    { ngx_string("internal_auth_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, timeout),
      NULL },
      
    { ngx_string("internal_auth_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, header_name),
      NULL },
      
      ngx_null_command
};


static ngx_http_module_t ngx_http_internal_auth_module_ctx = {
    ngx_http_internal_auth_add_variables,    /* preconfiguration */
    ngx_http_internal_auth_init,             /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    ngx_http_internal_auth_create_srv_conf,  /* create server configuration */
    ngx_http_internal_auth_merge_srv_conf,   /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};


ngx_module_t ngx_http_internal_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_internal_auth_module_ctx,      /* module context */
    ngx_http_internal_auth_commands,         /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_internal_auth_vars[] = {
    { ngx_string("internal_auth_result"), NULL,
      ngx_http_internal_auth_result_variable,
      0, 0, 0 },

    { ngx_string("internal_auth_proxy_fingerprint"), NULL,
      ngx_http_internal_auth_proxy_fingerprint_variable,
      0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t ngx_http_internal_auth_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_internal_auth_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_internal_auth_result_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_internal_auth_ctx_t *ctx;
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_internal_auth_module);

    if (!ctx || ctx->result.len <= 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->result.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->result.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_internal_auth_proxy_fingerprint_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_internal_auth_conf_t *conf;

    uint32_t   timestamp;
    u_char     timestamp_hex[9];
    u_char    *p;
    size_t     data_len;
    size_t     fingerprint_len;
    u_char    *fingerprint_data;
    ngx_str_t  computed_md5;

    timestamp = (uint32_t)ngx_time();
    p = timestamp_hex;
    p += ngx_sprintf(p, "%08xi", timestamp) - p;

    conf = ngx_http_get_module_srv_conf(r, ngx_http_internal_auth_module);

    data_len = conf->proxy_secret.len + 8;
    fingerprint_data = ngx_palloc(r->pool, data_len);
    if (fingerprint_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "failed to allocate memory for fingerprint_data");
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_memcpy(fingerprint_data,
        conf->proxy_secret.data, conf->proxy_secret.len);
    ngx_memcpy(fingerprint_data + conf->proxy_secret.len,
        timestamp_hex, 8);

    computed_md5 = ngx_http_internal_auth_compute_md5_hex(r,
        fingerprint_data, data_len);
    if (computed_md5.len != 32 || computed_md5.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "failed to compute md5sum for fingerprint");
        v->not_found = 1;
        return NGX_OK;
    }

    fingerprint_len = 40;
    v->data = ngx_palloc(r->pool, fingerprint_len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "failed to allocate memory for variable data");
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_memcpy(v->data, timestamp_hex, 8);
    ngx_memcpy(v->data + 8, computed_md5.data, 32);

    v->len = fingerprint_len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


char *
ngx_http_internal_auth_set_request_secrets_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t         *value, *s;
    ngx_array_t      **a;
    ngx_conf_post_t   *post;

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a != NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate directive \"%V\" is not allowed",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    *a = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (*a == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        s = ngx_array_push(*a);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }

        *s = value[i];
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, *a);
    }

    return NGX_CONF_OK;
}


static ngx_str_t
ngx_http_internal_auth_compute_md5_hex(ngx_http_request_t *r,
    const u_char *data, size_t len)
{
    ngx_md5_t md5;
    u_char digest[16];
    ngx_str_t md5_hex;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, data, len);
    ngx_md5_final(digest, &md5);
 
    md5_hex.len = 32;
    md5_hex.data = ngx_palloc(r->pool, md5_hex.len);
    if (md5_hex.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Failed to allocate memory for MD5 hex string");
        md5_hex.len = 0;
        return md5_hex;
    }

    ngx_hex_dump(md5_hex.data, digest, 16);

    return md5_hex;
}


static ngx_table_elt_t*
ngx_http_internal_auth_get_header(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *h = part->elts;

    for (ngx_uint_t i = 0; i < part->nelts; i++) {
        if (h[i].key.len == name->len &&
            ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {
            return &h[i];
        }
    }

    while (part->next != NULL) {
        part = part->next;
        h = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            if (h[i].key.len == name->len &&
                ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
            {
                return &h[i];
            }
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_internal_auth_deny(ngx_http_request_t *r,
    ngx_http_internal_auth_ctx_t *ctx, const char *log_message,
    ngx_uint_t deny_flag)
{
    ngx_str_set(&ctx->result, "failure");

    if (deny_flag) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", log_message);
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_internal_auth_handler(ngx_http_request_t *r)
{
    ngx_http_internal_auth_conf_t *conf;
    ngx_http_internal_auth_ctx_t  *ctx;
    ngx_table_elt_t               *h;
    ngx_str_t                      fingerprint_header;
    u_char                         timestamp_hex[9];
    u_char                         md5sum_data[33];
    ngx_str_t                      timestamp_hex, md5sum;
    time_t                         timestamp, current_time;
    ngx_uint_t                     i;
    ngx_str_t                      computed_md5;
    ngx_str_t                      data;

    conf = ngx_http_get_module_srv_conf(r, ngx_http_internal_auth_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_internal_auth_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_internal_auth_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_internal_auth_module);
    }

    if (!conf->enable) {
        ngx_str_set(&ctx->result, "off");
        return NGX_DECLINED;
    }

    h = ngx_http_internal_auth_get_header(r, &conf->header_name);
    if (h == NULL) {
        return ngx_http_internal_auth_deny(r, ctx,
            "internal auth denied access due to empty fingerprint",
            conf->empty_deny);
    }

    fingerprint_header = h->value;
    if (fingerprint_header.len < 40) {
        return ngx_http_internal_auth_deny(r, ctx,
            "internal auth denied access due to invalid fingerprint format",
            conf->failure_deny);
    }

    ngx_memcpy(timestamp_hex, fingerprint_header.data, 8);
    timestamp_hex[8] = '\0';
    ngx_memcpy(md5sum_data, fingerprint_header.data + 8, 32);
    md5sum_data[32] = '\0';

    md5sum.len = 32;
    md5sum.data = md5sum_data;

    timestamp = (time_t) ngx_hextoi(timestamp_hex, 8);
    if (timestamp == (time_t) NGX_ERROR || timestamp == 0) {
        return ngx_http_internal_auth_deny(r, ctx,
            "internal auth denied access due to invalid fingerprint timestamp",
            conf->failure_deny);
    }

    current_time = ngx_time();
    if ((current_time - timestamp) > conf->timeout) {
        return ngx_http_internal_auth_deny(r, ctx, 
            "internal auth denied access due to fingerprint timeout",
            conf->failure_deny);
    }

    if (conf->request_secrets == NULL || conf->request_secrets->nelts == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "internal auth skipped due to no configured secret");
        ngx_str_set(&ctx->result, "success");
        return NGX_DECLINED;
    }

    secret = conf->request_secrets->elts;
    for (i = 0; i < conf->request_secrets->nelts; i++) {
        data.len = secret[i].len + timestamp_hex.len;
        data.data = ngx_palloc(r->pool, data.len);
        if (data.data == NULL) {
            return ngx_http_internal_auth_deny(r, ctx,
                "failed to allocate memory for fingerprint data",
                conf->failure_deny);
        }

        ngx_memcpy(data.data, secret[i].data, secret[i].len);
        ngx_memcpy(data.data + secret[i].len, timestamp_hex, 8);

        computed_md5 = ngx_http_internal_auth_compute_md5_hex(r,
            data.data, data.len);

        if (computed_md5.len == 0) {
            return ngx_http_internal_auth_deny(r, ctx,
                "internal auth denied access due to empty fingerprint hash",
                conf->failure_deny);
        }

        if (computed_md5.len == md5sum.len
            && ngx_strncmp(computed_md5.data, md5sum.data, md5sum.len) == 0) {
            ngx_str_set(&ctx->result, "success");
            return NGX_DECLINED;
        }
    }

    return ngx_http_internal_auth_deny(r, ctx,
        "internal auth denied access due to fingerprint hash mismatch",
        conf->failure_deny);
}


static void *
ngx_http_internal_auth_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_internal_auth_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_internal_auth_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->proxy_secret = { 0, NULL };
     */

    conf->enable = NGX_CONF_UNSET;
    conf->request_secrets = NGX_CONF_UNSET_PTR;
    conf->empty_deny = NGX_CONF_UNSET;
    conf->failure_deny = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET;
    conf->header_name.len = 0;
    conf->header_name.data = NULL;

    return conf;
}


static char *
ngx_http_internal_auth_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_internal_auth_conf_t *prev = parent;
    ngx_http_internal_auth_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->request_secrets,
                              prev->request_secrets, NULL);
    ngx_conf_merge_str_value(conf->proxy_secret,
                              prev->proxy_secret, "");
    ngx_conf_merge_value(conf->empty_deny, prev->empty_deny, 0);
    ngx_conf_merge_value(conf->failure_deny, prev->failure_deny, 1);
    ngx_conf_merge_value(conf->timeout, prev->timeout, 300);
    ngx_conf_merge_str_value(conf->header_name, prev->header_name,
                              "X-Fingerprint");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_internal_auth_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_internal_auth_handler;

    return NGX_OK;
}
