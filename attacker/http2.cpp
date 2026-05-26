

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <nghttp2/nghttp2.h>

static int on_header_callback(nghttp2_session* session,
    const nghttp2_frame* frame,
    const uint8_t* name, size_t namelen,
    const uint8_t* value, size_t valuelen,
    uint8_t flags, void* user_data) {

    return 0;
}

static int on_send_callback(nghttp2_session* session,
    const uint8_t* data, size_t length,
    int flags, void* user_data) {

    return 0;
}



static int on_data_chunk_recv_callback(nghttp2_session* session,
    uint8_t flags,
    int32_t stream_id,
    const uint8_t* data,
    size_t len, void* user_data) {

    return 0;
}



int htp2Process(char * buf,int size) {
    nghttp2_session_callbacks* callbacks;
    nghttp2_session* session;

    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_on_header_callback(callbacks, (nghttp2_on_header_callback)on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, (nghttp2_on_data_chunk_recv_callback)on_data_chunk_recv_callback);
    // 必须设置 send_callback，即使你使用 mem_recv
    //nghttp2_session_callbacks_set_send_callback(callbacks, (nghttp2_send_callback)on_send_callback);

    int rv = nghttp2_session_client_new(&session, callbacks, NULL); 
    if (rv != 0) {
        printf("Session creation failed: %s\n", nghttp2_strerror(rv));
        return -1;
    }

    nghttp2_session_mem_recv(session,(unsigned char*) buf, size);

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(callbacks);
    return 0;
}
​