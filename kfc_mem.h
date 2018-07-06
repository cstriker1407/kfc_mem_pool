/*
一个基于bitmap方式的C语言版本的内存池实现
实现思路简单介绍：
1.单个内存节点为32Byte,申请内存时以32Byte为单位进行管理
2.节点使用情况使用bitmap数组进行管理,单个bitmap类型为UINT
3.考虑到实现复杂度和实际应用场景,内存池可分配的最大内存为32Byte * bitsof(UINT) * 2 = 2048Byte，超过此范围直接内部调用sys_malloc
PS：
1. only work at 32Bit System
2. written by cstriker1407@yeah.net   http://cstriker1407.info/blog/
3. Follow BSD
*/

#ifndef KFC_MEM_H
#define KFC_MEM_H

#include <stdio.h>
#include <string.h>
#define k_memset memset


#define k_null 0
#define kfc_debug(fmt, ...) printf("[DBG %4d]"fmt"\r\n", __LINE__, ##__VA_ARGS__)
#define kfc_error(fmt, ...) printf("[ERR %4d]"fmt"\r\n", __LINE__, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

int kfc_init( void *(*sys_malloc)(unsigned int size),
               void (*sys_free)(void *ptr),
               void (*sys_lock)(void),
               void (*sys_unlock)(void)
               );

void *kfc_calloc(unsigned int nmemb, unsigned int size);

void kfc_free(void *ptr);

void kfc_dump_mem_pool_bitmaps(void);
void kfc_update_mem_occupy_status(unsigned int *p_total_bits, unsigned int *p_used_bits,
                                  unsigned int *p_curr_occupy_user, unsigned int *p_max_occupy_user,
                                  unsigned int *p_curr_occupy_all, unsigned int *p_max_occupy_all
                                  );
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // KFC_MEM_H
