#include <stdio.h>
#include <stdlib.h>

#include "kfc_mem.h"


void *sys_malloc(unsigned int size)
{
    return malloc(size);
}

void sys_free(void *ptr)
{
    free(ptr);
}

void sys_lock(void)
{
//todo
}

void sys_unlock(void)
{
//todo
}

int main(void)
{
    printf("Hello World!\n");

    test_tool_funcs();
    kfc_init(sys_malloc, sys_free, sys_lock, sys_unlock);
    kfc_dump_mem_pool_bitmaps();

#if 0
    void *p1 = kfc_calloc(1, 1000); kfc_dump_mem_pool_bitmaps();
    void *p2 = kfc_calloc(1, 2000); kfc_dump_mem_pool_bitmaps();
    void *p3 = kfc_calloc(1, 100); kfc_dump_mem_pool_bitmaps();

    unsigned int total_bits = 0;
    unsigned int used_bits = 0;
    unsigned int curr_occupy_user = 0;
    unsigned int max_occupy_user = 0;
    unsigned int curr_occupy_all = 0;
    unsigned int max_occupy_all = 0;
    kfc_update_mem_occupy_status(&total_bits, &used_bits,
                                 &curr_occupy_user, &max_occupy_user,
                                 &curr_occupy_all, &max_occupy_all );

    kfc_free(p1); kfc_dump_mem_pool_bitmaps();
#endif

#if 1
    void *p1 = kfc_calloc(1, 20); kfc_dump_mem_pool_bitmaps();
    void *p2 = kfc_calloc(1, 32); kfc_dump_mem_pool_bitmaps();
    void *p3 = kfc_calloc(1, 34); kfc_dump_mem_pool_bitmaps();
    void *p4 = kfc_calloc(1, 62); kfc_dump_mem_pool_bitmaps();
    void *p5 = kfc_calloc(1, 64); kfc_dump_mem_pool_bitmaps();
    void *p6 = kfc_calloc(1, 65); kfc_dump_mem_pool_bitmaps();
    void *p7 = kfc_calloc(1, 2047); kfc_dump_mem_pool_bitmaps();
    void *p8 = kfc_calloc(1, 2048); kfc_dump_mem_pool_bitmaps();
    void *p9 = kfc_calloc(1, 2049); kfc_dump_mem_pool_bitmaps();

    kfc_free(p1); kfc_dump_mem_pool_bitmaps();
    kfc_free(p2); kfc_dump_mem_pool_bitmaps();
    kfc_free(p3); kfc_dump_mem_pool_bitmaps();
    kfc_free(p4); kfc_dump_mem_pool_bitmaps();
    kfc_free(p5); kfc_dump_mem_pool_bitmaps();
    kfc_free(p6); kfc_dump_mem_pool_bitmaps();
    kfc_free(p7); kfc_dump_mem_pool_bitmaps();
    kfc_free(p8); kfc_dump_mem_pool_bitmaps();
    kfc_free(p9); kfc_dump_mem_pool_bitmaps();
#endif
    return 0;
}
