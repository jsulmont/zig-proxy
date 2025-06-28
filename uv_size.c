#include <stdio.h>
#include <stddef.h>
#include <uv.h>

#define PRINT_SIZE_ALIGN(type) \
    printf("%-20s size: %3zu bytes, align: %2zu\n", #type, sizeof(type), _Alignof(type))

int main() {
    printf("libuv struct sizes and alignments:\n");
    printf("=====================================\n");
    
    // Core types
    PRINT_SIZE_ALIGN(uv_loop_t);
    PRINT_SIZE_ALIGN(uv_handle_t);
    
    // Handle types
    PRINT_SIZE_ALIGN(uv_tcp_t);
    PRINT_SIZE_ALIGN(uv_udp_t);
    PRINT_SIZE_ALIGN(uv_pipe_t);
    PRINT_SIZE_ALIGN(uv_timer_t);
    PRINT_SIZE_ALIGN(uv_prepare_t);
    PRINT_SIZE_ALIGN(uv_check_t);
    PRINT_SIZE_ALIGN(uv_idle_t);
    PRINT_SIZE_ALIGN(uv_async_t);
    PRINT_SIZE_ALIGN(uv_poll_t);
    PRINT_SIZE_ALIGN(uv_signal_t);
    PRINT_SIZE_ALIGN(uv_process_t);
    PRINT_SIZE_ALIGN(uv_tty_t);
    
    printf("\n");
    
    // Request types
    PRINT_SIZE_ALIGN(uv_req_t);
    PRINT_SIZE_ALIGN(uv_write_t);
    PRINT_SIZE_ALIGN(uv_connect_t);
    PRINT_SIZE_ALIGN(uv_shutdown_t);
    PRINT_SIZE_ALIGN(uv_udp_send_t);
    PRINT_SIZE_ALIGN(uv_fs_t);
    PRINT_SIZE_ALIGN(uv_work_t);
    PRINT_SIZE_ALIGN(uv_getaddrinfo_t);
    PRINT_SIZE_ALIGN(uv_getnameinfo_t);
    
    printf("\n");
    
    // Other important types
    PRINT_SIZE_ALIGN(uv_buf_t);
    PRINT_SIZE_ALIGN(struct sockaddr);
    PRINT_SIZE_ALIGN(struct sockaddr_in);
    PRINT_SIZE_ALIGN(struct sockaddr_in6);
    
    printf("\n");
    printf("Pointer size: %zu bytes, align: %zu\n", sizeof(void*), _Alignof(void*));
    
    return 0;
}
