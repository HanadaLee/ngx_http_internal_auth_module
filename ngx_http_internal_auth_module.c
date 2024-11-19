#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

/* 请求上下文结构体 */
typedef struct {
    ngx_str_t internal_auth_result;
} ngx_http_internal_auth_ctx_t;

/* 配置结构体 */
typedef struct {
    ngx_flag_t   auth_enabled;      /* internal_request_auth on/off */
    ngx_str_t    secret;            /* internal_request_auth_secret */
    ngx_flag_t   empty_deny;        /* internal_request_auth_empty_deny on/off */
    ngx_flag_t   failure_deny;      /* internal_request_auth_failure_deny on/off */
    ngx_uint_t   timeout;           /* internal_request_auth_timeout，秒 */
    ngx_str_t    header_name;       /* internal_request_auth_header */
} ngx_http_internal_auth_conf_t;

/* 函数声明 */
static ngx_int_t ngx_http_internal_auth_handler(ngx_http_request_t *r);
static void *ngx_http_internal_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_internal_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_internal_auth_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_internal_auth_variable_result(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_internal_auth_variable_fingerprint(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_table_elt_t* ngx_http_internal_auth_get_header(ngx_http_request_t *r, ngx_str_t *name);

/* 模块指令 */
static ngx_command_t ngx_http_internal_auth_commands[] = {
    { ngx_string("internal_request_auth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, auth_enabled),
      NULL },
      
    { ngx_string("internal_request_auth_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, secret),
      NULL },
      
    { ngx_string("internal_request_auth_empty_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, empty_deny),
      NULL },
      
    { ngx_string("internal_request_auth_failure_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, failure_deny),
      NULL },
      
    { ngx_string("internal_request_auth_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, timeout),
      NULL },
      
    { ngx_string("internal_request_auth_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_internal_auth_conf_t, header_name),
      NULL },
      
    ngx_null_command
};

/* 模块上下文 */
static ngx_http_module_t ngx_http_internal_auth_module_ctx = {
    NULL,                                /* preconfiguration */
    ngx_http_internal_auth_init,         /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    ngx_http_internal_auth_create_loc_conf, /* create location configuration */
    ngx_http_internal_auth_merge_loc_conf   /* merge location configuration */
};

/* 定义模块 */
ngx_module_t ngx_http_internal_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_internal_auth_module_ctx, /* module context */
    ngx_http_internal_auth_commands,    /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};

/* 创建 location 配置 */
static void *
ngx_http_internal_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_internal_auth_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_internal_auth_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* 设置默认值 */
    conf->auth_enabled = NGX_CONF_UNSET;
    conf->empty_deny = NGX_CONF_UNSET;
    conf->failure_deny = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_UINT;
    conf->header_name.len = 0;
    conf->header_name.data = NULL;

    return conf;
}

/* 合并配置 */
static char *
ngx_http_internal_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_internal_auth_conf_t *prev = parent;
    ngx_http_internal_auth_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->auth_enabled, prev->auth_enabled, 0);
    ngx_conf_merge_off_value(conf->empty_deny, prev->empty_deny, 0);
    ngx_conf_merge_off_value(conf->failure_deny, prev->failure_deny, 1);
    ngx_conf_merge_uint_value(conf->timeout, prev->timeout, 300); /* 使用 ngx_conf_merge_uint_value */
    ngx_conf_merge_str_value(conf->header_name, prev->header_name, "X-Fingerprint");

    return NGX_CONF_OK;
}

/* 计算 MD5 并转换为十六进制字符串 */
static ngx_str_t
ngx_http_internal_auth_compute_md5_hex(ngx_http_request_t *r, const u_char *data, size_t len)
{
    ngx_md5_t md5;
    u_char digest[16];
    ngx_str_t md5_hex;

    // 初始化 MD5 计算
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, data, len);
    ngx_md5_final(digest, &md5);

    // 分配内存
    md5_hex.len = 32;
    md5_hex.data = ngx_palloc(r->pool, md5_hex.len); // 使用请求的内存池
    if (md5_hex.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Failed to allocate memory for MD5 hex string");
        md5_hex.len = 0;
        return md5_hex;
    }

    // 使用 ngx_hex_dump 将 MD5 的二进制数据转换为十六进制字符串
    ngx_hex_dump(md5_hex.data, digest, 16);

    return md5_hex;
}


/* 复制字符串 */
static ngx_str_t
ngx_http_internal_auth_string_n_copy(const u_char *src, size_t n, ngx_pool_t *pool)
{
    ngx_str_t s;
    s.len = n;
    s.data = ngx_pnalloc(pool, n);
    if (s.data != NULL) {
        ngx_memcpy(s.data, src, n);
    }
    return s;
}

/* 查找请求头 */
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

/* 变量处理函数 - $internal_auth_result */
static ngx_int_t
ngx_http_internal_auth_variable_result(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_internal_auth_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_internal_auth_module);
    if (ctx && ctx->internal_auth_result.len > 0) {
        v->len = ctx->internal_auth_result.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->internal_auth_result.data;
    } else {
        /* 重新调用 handler */
        ngx_int_t rc = ngx_http_internal_auth_handler(r);
        if (rc == NGX_DECLINED || rc == NGX_HTTP_FORBIDDEN) {
            ctx = ngx_http_get_module_ctx(r, ngx_http_internal_auth_module);
            if (ctx && ctx->internal_auth_result.len > 0) {
                v->len = ctx->internal_auth_result.len;
                v->valid = 1;
                v->no_cacheable = 0;
                v->not_found = 0;
                v->data = ctx->internal_auth_result.data;
            } else {
                v->not_found = 1;
            }
        } else {
            v->not_found = 1;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_internal_auth_variable_fingerprint(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_internal_auth_conf_t *conf;
    

    uint32_t timestamp;
    u_char   timestamp_hex[9];
    u_char  *p;
    size_t data_len, fingerprint_len;
    u_char *fingerprint_data;
    ngx_str_t computed_md5;

    timestamp = (uint32_t)ngx_time();
    p = timestamp_hex;
    p += ngx_sprintf(p, "%08xi", timestamp) - p;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_internal_auth_module);
    // 拼接 secret + timestamp_hex
    data_len = conf->secret.len + 8;
    fingerprint_data = ngx_palloc(r->pool, data_len);
    if (fingerprint_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory for fingerprint_data");
        v->not_found = 1;
        return NGX_OK;
    }
    ngx_memcpy(fingerprint_data, conf->secret.data, conf->secret.len);
    ngx_memcpy(fingerprint_data + conf->secret.len, timestamp_hex, 8);

    // 计算 MD5
    computed_md5 = ngx_http_internal_auth_compute_md5_hex(r, fingerprint_data, data_len);
    if (computed_md5.len != 32 || computed_md5.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to compute MD5 for fingerprint");
        v->not_found = 1;
        return NGX_OK;
    }

    // 分配池内存存储结果
    fingerprint_len = 40;
    v->data = ngx_palloc(r->pool, fingerprint_len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory for variable data");
        v->not_found = 1;
        return NGX_OK;
    }

    // 拼接 timestamp_hex 和 md5_hex
    ngx_memcpy(v->data, timestamp_hex, 8);
    ngx_memcpy(v->data + 8, computed_md5.data, 32);

    // 设置变量
    v->len = fingerprint_len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


/* 定义变量 */
static ngx_http_variable_t ngx_http_internal_auth_vars[] = {
    { ngx_string("internal_auth_result"), NULL, ngx_http_internal_auth_variable_result, 0, 0, 0 },
    { ngx_string("internal_auth_fingerprint"), NULL, ngx_http_internal_auth_variable_fingerprint, 0, 0, 0 },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

/* Handler函数 */
static ngx_int_t
ngx_http_internal_auth_handler(ngx_http_request_t *r)
{
    ngx_http_internal_auth_conf_t *conf;
    ngx_http_internal_auth_ctx_t *ctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_internal_auth_module);

    /* 获取或创建上下文 */
    ctx = ngx_http_get_module_ctx(r, ngx_http_internal_auth_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_internal_auth_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_internal_auth_module);
    }

    /* 如果 internal_auth_result 已经有结果，则直接返回 */
    if (ctx->internal_auth_result.len > 0) {
        return NGX_DECLINED;
    }

    if (!conf->auth_enabled) {
        ngx_str_set(&ctx->internal_auth_result, "off"); /* 使用 ngx_str_set 宏 */
        return NGX_DECLINED;
    }

    /* 获取请求头 */
    ngx_table_elt_t *h = ngx_http_internal_auth_get_header(r, &conf->header_name);
    if (h == NULL) {
        if (conf->empty_deny) {
            ngx_str_set(&ctx->internal_auth_result, "empty");
            return NGX_HTTP_FORBIDDEN;
        } else {
            ngx_str_set(&ctx->internal_auth_result, "success");
            return NGX_DECLINED;
        }
    }

    ngx_str_t fingerprint_header = h->value;

    if (fingerprint_header.len < 8) {
        if (conf->failure_deny) {
            ngx_str_set(&ctx->internal_auth_result, "failure");
            return NGX_HTTP_FORBIDDEN;
        } else {
            ngx_str_set(&ctx->internal_auth_result, "success");
            return NGX_DECLINED;
        }
    }

    /* 提取时间戳和 md5sum */
    ngx_str_t timestamp_hex = ngx_http_internal_auth_string_n_copy(fingerprint_header.data, 8, r->pool);
    ngx_str_t md5sum = ngx_http_internal_auth_string_n_copy(fingerprint_header.data + 8, fingerprint_header.len - 8, r->pool);

    /* 转换时间戳 */
    unsigned long timestamp = strtoul((char *)timestamp_hex.data, NULL, 16);
    if (timestamp == 0) {
        if (conf->failure_deny) {
            ngx_str_set(&ctx->internal_auth_result, "failure");
            return NGX_HTTP_FORBIDDEN;
        } else {
            ngx_str_set(&ctx->internal_auth_result, "success");
            return NGX_DECLINED;
        }
    }

    /* 获取当前时间 */
    ngx_time_t *tp = ngx_timeofday();
    if (tp == NULL) {
        if (conf->failure_deny) {
            ngx_str_set(&ctx->internal_auth_result, "failure");
            return NGX_HTTP_FORBIDDEN;
        } else {
            ngx_str_set(&ctx->internal_auth_result, "success");
            return NGX_DECLINED;
        }
    }
    unsigned long current_time = tp->sec;

    if ((current_time - timestamp) > conf->timeout) {
        if (conf->failure_deny) {
            ngx_str_set(&ctx->internal_auth_result, "failure");
            return NGX_HTTP_FORBIDDEN;
        } else {
            ngx_str_set(&ctx->internal_auth_result, "success");
            return NGX_DECLINED;
        }
    }

    /* 校验 MD5 */
    size_t data_len = conf->secret.len + timestamp_hex.len;
    ngx_str_t data;
    data.len = data_len;
    data.data = ngx_palloc(r->pool, data_len);
    if (data.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(data.data, conf->secret.data, conf->secret.len);
    ngx_memcpy(data.data + conf->secret.len, timestamp_hex.data, timestamp_hex.len);

    ngx_str_t computed_md5 = ngx_http_internal_auth_compute_md5_hex(r, data.data, data.len);
    if (computed_md5.len == 0) {
        if (conf->failure_deny) {
            ngx_str_set(&ctx->internal_auth_result, "failure");
            return NGX_HTTP_FORBIDDEN;
        } else {
            ngx_str_set(&ctx->internal_auth_result, "success");
            return NGX_DECLINED;
        }
    }

    if (computed_md5.len != md5sum.len || ngx_strncmp(computed_md5.data, md5sum.data, md5sum.len) != 0) {
        if (conf->failure_deny) {
            ngx_str_set(&ctx->internal_auth_result, "failure");
            return NGX_HTTP_FORBIDDEN;
        } else {
            ngx_str_set(&ctx->internal_auth_result, "success");
            return NGX_DECLINED;
        }
    }

    /* 如果所有检查通过 */
    ngx_str_set(&ctx->internal_auth_result, "success");

    return NGX_DECLINED;
}

/* 模块初始化函数 */
static ngx_int_t
ngx_http_internal_auth_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_uint_t                  i;
    ngx_http_variable_t        *var;

    /* 注册变量 */
    for (i = 0; ngx_http_internal_auth_vars[i].name.len; i++) {
        var = ngx_http_add_variable(cf, &ngx_http_internal_auth_vars[i].name, NGX_HTTP_VAR_CHANGEABLE);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = ngx_http_internal_auth_vars[i].get_handler;
        var->data = ngx_http_internal_auth_vars[i].data;
    }

    /* 获取核心模块的主配置 */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* 挂载 handler 到 ACCESS 阶段 */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_internal_auth_handler;

    return NGX_OK;
}
