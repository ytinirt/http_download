#ifndef __HTTP_DOWNLOAD_H__
#define __HTTP_DOWNLOAD_H__

#include <sys/time.h>
#include "list.h"

#define HTTP_DL_BUF_LEN         128
#define HTTP_DL_HOST_LEN        HTTP_DL_BUF_LEN
#define HTTP_DL_PATH_LEN        HTTP_DL_BUF_LEN
#define HTTP_DL_URL_LEN         (HTTP_DL_HOST_LEN + HTTP_DL_PATH_LEN)
#define HTTP_DL_LOCAL_LEN       HTTP_DL_BUF_LEN
#define HTTP_DL_READBUF_LEN     4096

#define HTTP_DL_READ_TIMEOUT    10  /* 单位秒 */

typedef int bool;
#define true 1
#define false 0

typedef struct http_dl_rbuf_s {
    int fd;
    char buffer[4096];              /* the input buffer */
    char *buffer_pos;               /* current position in the buffer */
    size_t buffer_left;             /* number of bytes left in the buffer:
                                       buffer_left = buffer_end - buffer_pos */
    int internal_dont_touch_this;   /* used by RBUF_READCHAR macro */
} http_dl_rbuf_t;

typedef enum http_dl_stage_e {
    HTTP_DL_STAGE_INIT = 0,         /* 下载任务建立时初始状态 */
    HTTP_DL_STAGE_SEND_REQUEST,     /* 发送下载请求到服务器，当连接成功建立后置 */
    HTTP_DL_STAGE_PARSE_STATUS_LINE,/* 解析状态行 */
    HTTP_DL_STAGE_PARSE_HEADER,     /* 解析头部 */
    HTTP_DL_STAGE_RECV_CONTENT,     /* 接收包体内容 */
    HTTP_DL_STAGE_FINISH,           /* 下载完成，如果异常完成，则将错误信息记录到err_msg中 */
} http_dl_stage_t;

#define HTTP_DL_F_GENUINE_AGENT 0x00000001UL

typedef struct http_dl_info_s {
    http_dl_stage_t stage;
    unsigned long flags;

    struct list_head list;

    char url[HTTP_DL_URL_LEN];      /* Unchanged URL */
    char host[HTTP_DL_HOST_LEN];    /* Extracted hostname */
    char path[HTTP_DL_PATH_LEN];    /* Path, as well as dir and file (properly decoded) */
    char local[HTTP_DL_LOCAL_LEN];  /* The local filename of the URL document */
    unsigned short port;

    int sockfd;
    int filefd;

    char buf[HTTP_DL_READBUF_LEN];
    char *buf_data;
    char *buf_tail;

    long recv_len;                  /* received length */
    long content_len;               /* this HTTP session expected length */
    long restart_len;               /* the restart value, for range */
    int status_code;

    char err_msg[HTTP_DL_BUF_LEN];

    struct timeval start_time;      /* Get content's start time */
    unsigned long elapsed_time;     /* Duration time of getting contents */
} http_dl_info_t;

typedef struct http_dl_list_s {
    char name[HTTP_DL_BUF_LEN];
    struct list_head list;
    int count;
    int maxfd;
} http_dl_list_t;

typedef struct http_dl_range_s {
    long first_byte_pos;
    long last_byte_pos;
    long entity_length;
} http_dl_range_t;

typedef enum http_dl_err_e {
    HTTP_DL_OK = 0,
    HTTP_DL_ERR_INVALID = 1,        /* 0 stands for success, so errors begin with 1 */
    HTTP_DL_ERR_INTERNAL,
    HTTP_DL_ERR_SOCK,
    HTTP_DL_ERR_CONN,
    HTTP_DL_ERR_FOPEN,
    HTTP_DL_ERR_WRITE,
    HTTP_DL_ERR_READ,
    HTTP_DL_ERR_EOF,
    HTTP_DL_ERR_RESOURCE,
} http_dl_err_t;

#define HTTP_URL_PREFIX    "http://"
#define HTTP_URL_PRE_LEN    7       /* strlen("http://") */

#define HTTP_ACCEPT "*/*"
/* HTTP/1.0 status codes from RFC1945, provided for reference.  */
/* Successful 2xx.  */
#define HTTP_STATUS_OK			        200
#define HTTP_STATUS_CREATED		        201
#define HTTP_STATUS_ACCEPTED		    202
#define HTTP_STATUS_NO_CONTENT		    204
#define HTTP_STATUS_PARTIAL_CONTENTS	206

/* Redirection 3xx.  */
#define HTTP_STATUS_MULTIPLE_CHOICES	300
#define HTTP_STATUS_MOVED_PERMANENTLY	301
#define HTTP_STATUS_MOVED_TEMPORARILY	302
#define HTTP_STATUS_NOT_MODIFIED	    304

/* Client error 4xx.  */
#define HTTP_STATUS_BAD_REQUEST		    400
#define HTTP_STATUS_UNAUTHORIZED	    401
#define HTTP_STATUS_FORBIDDEN		    403
#define HTTP_STATUS_NOT_FOUND		    404

/* Server errors 5xx.  */
#define HTTP_STATUS_INTERNAL		    500
#define HTTP_STATUS_NOT_IMPLEMENTED	    501
#define HTTP_STATUS_BAD_GATEWAY		    502
#define HTTP_STATUS_UNAVAILABLE		    503
#define H_20X(x)        (((x) >= 200) && ((x) < 300))
#define H_PARTIAL(x)    ((x) == HTTP_STATUS_PARTIAL_CONTENTS)
#define H_REDIRECTED(x) (((x) == HTTP_STATUS_MOVED_PERMANENTLY)	\
			 || ((x) == HTTP_STATUS_MOVED_TEMPORARILY))
			 
/* The smaller value of the two.  */
#define MINVAL(x, y) ((x) < (y) ? (x) : (y))

#define RBUF_FD(rbuf) ((rbuf)->fd)
#define TEXTHTML_S "text/html"

#define http_dl_rbuf_readc(rbuf, store)					\
    ((rbuf)->buffer_left							\
     ? (--(rbuf)->buffer_left,						\
        *((char *) (store)) = *(rbuf)->buffer_pos++, 1)			\
     : ((rbuf)->buffer_pos = (rbuf)->buffer,				\
        ((((rbuf)->internal_dont_touch_this					\
           = http_dl_iread ((rbuf)->fd, (rbuf)->buffer,				\
    		sizeof ((rbuf)->buffer))) <= 0)				\
         ? (rbuf)->internal_dont_touch_this					\
         : ((rbuf)->buffer_left = (rbuf)->internal_dont_touch_this - 1,	\
    	*((char *) (store)) = *(rbuf)->buffer_pos++,			\
    	1))))

#define http_dl_free(foo) \
    do {    \
        if (foo) {  \
            free(foo);  \
        }   \
    } while (0)

extern int http_dl_log_level;

#define http_dl_log_info(fmt, arg...) \
    do { \
        if (http_dl_log_level >= 6) { \
            printf("*INFO*  %s: " fmt "\n", __func__, ##arg); \
        } else { \
            printf(fmt "\n", ##arg); \
        } \
    } while (0)

#define http_dl_log_debug(fmt, arg...) \
    do { \
        if (http_dl_log_level >= 7) { \
            printf("*DEBUG* %s[%d]: " fmt "\n", __func__, __LINE__, ##arg); \
        } \
    } while (0)
        
#define http_dl_log_error(fmt, arg...) \
    do { \
        if (http_dl_log_level >= 3) { \
            printf("*ERROR* %s[%d]: " fmt "\n", __func__, __LINE__, ##arg); \
        } \
    } while (0)

#define http_dl_print_raw(fmt, arg...) \
    do { \
        printf(fmt, ##arg); \
    } while(0)

#endif /* __HTTP_DOWNLOAD_H__ */

