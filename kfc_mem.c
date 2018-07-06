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

#include "kfc_mem.h"

typedef struct __kfc_mem_node
{
    unsigned char v1;
    unsigned char v2;
    unsigned char p_mem[2];
} kmem_node;

#define KFC_NODE_SIZE    2                      //内部数据结构大小
#define KFC_MAX_BUF_SIZE 0xFFFF                 //最大支持内存申请大小

//设置节点内存
#define KFC_NODE_SET_MEM_SIZE(p_node, target_size) \
do {p_node->v1 = target_size >> 8; p_node->v2 = target_size & 0xFF;} while(0)

//获取节点内存
#define KFC_NODE_GET_MEM_SIZE(p_node) ( (p_node->v1 << 8) | (p_node->v2) )

//当前内存占用和最大内存占用，包括用户实际获取的裸内存和外部包装后的内存
static unsigned int s_curr_occupy_user = 0;
static unsigned int s_max_occupy_user = 0;
static unsigned int s_curr_occupy_all = 0;
static unsigned int s_max_occupy_all = 0;

//函数指针
static void *(*s_p_malloc)(unsigned int size) = k_null;
static void (*s_p_free)(void *ptr) = k_null;
static void (*s_p_lock)(void) = k_null;
static void (*s_p_unlock)(void) = k_null;


#define KFC_MEM_POOL_UNIT_SIZE       32             //内存池内存单元
#define KFC_MEM_POOL_UNIT_BITS_SCAL  5              //内存池内存单元的偏移量 32 = 1<<5
#define KFC_MEM_POOL_UNIT_REVERSE    0xFFFFFFE0     //内存池内存单元的反向值

#define KFC_MEM_POOL_UNIT_NUM        2048           //内存池单元个数
#define KFC_INT_BITS_SCAL            5              //使用UINT作为bitmap管理单元，一个UINT有32位，32 = 1<<5
#define KFC_INT_BITS_NUM             32             //使用UINT作为bitmap管理单元，一个UINT有32位
//用uint和bitmap进行管理内存池单元，所需要的uint数目
#define KFC_MEM_BITMAP_CNT      (KFC_MEM_POOL_UNIT_NUM >> KFC_INT_BITS_SCAL)

//0:空闲，1：使用中
static unsigned int s_mem_pool_bitmap[KFC_MEM_BITMAP_CNT] = {0};

/* 内存池实际地址 */
static void *s_p_mem_pool_start = k_null;
static void *s_p_mem_pool_end = k_null;

//判断内存是否属于内存池
#define KFC_CHECK_NODE_IN_MEM_POOL(ptr) \
( ((unsigned long)ptr >= (unsigned long)s_p_mem_pool_start) && ((unsigned long)ptr < (unsigned long)s_p_mem_pool_end) )

/* 预定义的用来进行对比测试的数组 */
static const unsigned int s_uint_arr[KFC_INT_BITS_NUM] =
{
0x01,0x03,0x07,0x0F,0x1F,0x3F,0x7F,0xFF,
0x1FF,0x3FF,0x7FF,0xFFF,0x1FFF,0x3FFF,0x7FFF,0xFFFF,
0x1FFFF,0x3FFFF,0x7FFFF,0xFFFFF,0x1FFFFF,0x3FFFFF,0x7FFFFF,0xFFFFFF,
0x1FFFFFF,0x3FFFFFF,0x7FFFFFF,0xFFFFFFF,0x1FFFFFFF,0x3FFFFFFF,0x7FFFFFFF,0xFFFFFFFF
};


/* 输入大小32字节对齐 KFC_MEM_POOL_UNIT_SIZE  */
static inline unsigned int __upper_input(unsigned int input)
{
    unsigned int output = input & KFC_MEM_POOL_UNIT_REVERSE;
    if(output != input)
        output = ((output >> KFC_MEM_POOL_UNIT_BITS_SCAL) + 1) << KFC_MEM_POOL_UNIT_BITS_SCAL;

//    kfc_debug("input [ %u ] upper 32 scale and output [ %u ]", input, output);
    return output;
}

/* 获取一个uint从右侧开始的连续0的数目 */
static inline int __get_free_cnt_in_uint_right(unsigned int input)
{
    int tmp_idx = 0;
    for(tmp_idx = 0; tmp_idx < KFC_INT_BITS_NUM; tmp_idx++)
    {
        if( (input & s_uint_arr[tmp_idx]) != 0 )
        {
            break;
        }
    }
    kfc_debug("calc input[ 0x%x ],avail cnt in right:%d", input, tmp_idx);
    return tmp_idx;
}

/* 获取一个uint从左侧开始的连续0的数目 */
static inline int __get_free_cnt_in_uint_left(unsigned int input)
{
    int tmp_idx = 0;
    for(tmp_idx = 0; tmp_idx < KFC_INT_BITS_NUM; tmp_idx++)
    {
        if( (input & (s_uint_arr[tmp_idx] << (KFC_INT_BITS_NUM - 1 - tmp_idx) ) ) != 0 )
        {
            break;
        }
    }
    kfc_debug("calc input[ 0x%x ],avail cnt in left:%d", input, tmp_idx);
    return tmp_idx;
}

/* 获取一个uint从左侧开始，有连续count个数的位置 */
static inline int __get_free_bits_idx_in_int_all(unsigned int input, unsigned int count)
{
    if(0 == input)
    {
        kfc_debug("calc input is 0, all free space");
        return 0;
    }

    if(0xFFFFFFFF == input)
    {
        kfc_debug("calc input is 0xFFFFFFFF, no free space");
        return -1;
    }

    unsigned int test_int = s_uint_arr[count - 1];
    unsigned int tmp_idx = 0;
    for(tmp_idx = 0; tmp_idx < KFC_INT_BITS_NUM - count; tmp_idx++)
    {
        unsigned int filter_val = input & (test_int << (KFC_INT_BITS_NUM - count - tmp_idx));

        if(filter_val == 0)
        {
            kfc_debug("calc input[ 0x%x ] and count[ %d ],find free idx[ %d ]", input, count, tmp_idx);
            return tmp_idx;
        }
    }

    kfc_debug("calc input[ 0x%x ] and count[ %d ], no free space", input, count);
    return -1;
}

/* 标记bitmap */
static inline void __mark_mem_pool_bitmap(unsigned int start_idx, unsigned int count, int set1)
{
    unsigned int base_idx = start_idx >> KFC_INT_BITS_SCAL;
    unsigned int offset_in_int = start_idx - (base_idx << KFC_INT_BITS_SCAL);
    unsigned int tmp = 0;
    kfc_debug("mark bitmaps start_idx:%d count:%d set1:%d  base_idx:%u offset_in_int:%u", start_idx, count, set1, base_idx, offset_in_int);

    for(tmp = 0; tmp < count; tmp++)
    {
        if(1 == set1)
            s_mem_pool_bitmap[base_idx] |= (1 << (KFC_INT_BITS_NUM - 1 - offset_in_int));
        else
            s_mem_pool_bitmap[base_idx] ^= (1 << (KFC_INT_BITS_NUM - 1 - offset_in_int));

        offset_in_int++;
        if(offset_in_int >= KFC_INT_BITS_NUM)
        {
            offset_in_int = 0;
            base_idx++;
        }
    }
}

/* 更新内存使用统计 */
static inline void __update_mem_occupy(unsigned int user_size, unsigned int all_size, int is_add)
{
    if(1 == is_add)
    {
        s_curr_occupy_all += all_size;
        s_curr_occupy_user += user_size;
    }
    else
    {
        s_curr_occupy_all -= all_size;
        s_curr_occupy_user -= user_size;
    }

    if(s_curr_occupy_all > s_max_occupy_all)
        s_max_occupy_all = s_curr_occupy_all;

    if(s_curr_occupy_user > s_max_occupy_user)
        s_max_occupy_user = s_curr_occupy_user;
}

/* 根据传入指针判断是否属于内存池 */
static inline kmem_node *__check_mem_from_mem_pool(void *p_mem)
{
    kmem_node *p_node = (kmem_node *)(p_mem - KFC_NODE_SIZE);
    if(KFC_CHECK_NODE_IN_MEM_POOL(p_node) == 1)
    {
        kfc_debug("kmem_node in mem_pool");
        return p_node;
    }else
    {
        kfc_debug("kmem_node not in the mem_pool");
        return k_null;
    }
}

/* 判断申请大小能否从内存池中申请 */
static inline int __check_size_fit_mem_pool(unsigned int target_size)
{
    unsigned int need_bits_num = __upper_input(target_size + KFC_NODE_SIZE) >> KFC_MEM_POOL_UNIT_BITS_SCAL;
    if(need_bits_num > (1 << (KFC_INT_BITS_SCAL + 1)))
    { /* 如果需要的bit数目>64，此时最少需要3个bitmap管理单元(1个管理单元最多可以管理32个bit)，
        此时申请内存需要大于 64*32 = 2048Byte,这种数量级别的内存无需使用内存池，而且3个及以上bitmap管理
        会很复杂。*/
        kfc_debug("calc size[ %u ] need bits[ %u ] not fit mem_pool", target_size, need_bits_num);
        return -1;
    }

    kfc_debug("calc size[ %u ] need bits[ %u ] fit mem_pool", target_size, need_bits_num);
    return 0;
}

/* 从内存池中释放内存 */
static inline void __free_from_mem_pool(kmem_node *p_node)
{
    unsigned int real_size = __upper_input(KFC_NODE_GET_MEM_SIZE(p_node) + KFC_NODE_SIZE);
    unsigned int start_idx = ( (unsigned long)p_node - (unsigned long)s_p_mem_pool_start ) >> KFC_MEM_POOL_UNIT_BITS_SCAL;
    unsigned int count = real_size >>KFC_MEM_POOL_UNIT_BITS_SCAL;
    kfc_debug("free from mem_pool start_idx:%d count:%d", start_idx, count);
    __mark_mem_pool_bitmap(start_idx, count, 0);
    __update_mem_occupy(KFC_NODE_GET_MEM_SIZE(p_node), real_size, 0);
}

/* 从内存池中申请内存 */
static inline kmem_node *__malloc_from_mem_pool(unsigned int target_size)
{   /* 如果需要的bit数目<=64，此时最多只有2个bitmap管理单元会被命中(1个管理单元最多可以管理32个bit)  */
    unsigned int need_bits_num = __upper_input(target_size + KFC_NODE_SIZE) >> KFC_MEM_POOL_UNIT_BITS_SCAL;
    int tmp_idx = 0;
    kfc_debug("input size[ %d ] calc bits[ %u ]", target_size, need_bits_num);
    for(tmp_idx = 0; tmp_idx < KFC_MEM_BITMAP_CNT; tmp_idx++)
    {
        int start_bits = 0;
        if(need_bits_num <= (1 << KFC_INT_BITS_SCAL))
        {//如果需要的bit数目<=32，那么1个管理单元就可以满足，优先查找。
            start_bits = __get_free_bits_idx_in_int_all(s_mem_pool_bitmap[tmp_idx], need_bits_num);
        }else
        {//如果需要的bit数目为33个，那么直接跳过1个管理单元查询。
            start_bits = -1;
        }
        if(start_bits >= 0)
        {//找到满足需要的区间
            kfc_debug("find free in one bitmap. start_bits:%d idx:%d", start_bits, tmp_idx);
            start_bits += (tmp_idx << KFC_INT_BITS_SCAL);
            __mark_mem_pool_bitmap(start_bits, need_bits_num, 1);
            __update_mem_occupy(target_size, need_bits_num << KFC_MEM_POOL_UNIT_BITS_SCAL, 1);
            return (kmem_node *)(s_p_mem_pool_start + (start_bits << KFC_MEM_POOL_UNIT_BITS_SCAL));
        }else
        {//1个管理单元里找不到，2个里面找
            if(tmp_idx == KFC_MEM_BITMAP_CNT - 1)
            {
                kfc_debug("reach mem_pool end");
                continue;
            }

            unsigned int head_cnt = __get_free_cnt_in_uint_right(s_mem_pool_bitmap[tmp_idx]);
            unsigned int tail_cnt = __get_free_cnt_in_uint_left(s_mem_pool_bitmap[tmp_idx + 1]);
            if(head_cnt + tail_cnt >= need_bits_num)
            {//找到满足需要的区间
                kfc_debug("find free in two bitmaps.index:%u(%u) %u(%u)", tmp_idx, head_cnt, tmp_idx + 1, tail_cnt);
                start_bits = (1 << KFC_INT_BITS_SCAL) - head_cnt + (tmp_idx << KFC_INT_BITS_SCAL);
                __mark_mem_pool_bitmap(start_bits, need_bits_num, 1);
                __update_mem_occupy(target_size, need_bits_num << KFC_MEM_POOL_UNIT_BITS_SCAL, 1);
                return (kmem_node *)(s_p_mem_pool_start + (start_bits << KFC_MEM_POOL_UNIT_BITS_SCAL));
            }else
            {
                kfc_debug("index:%u(%u) %u(%u) not have enough free mem.check next couple.", tmp_idx, head_cnt, tmp_idx + 1, tail_cnt);
            }
        }
    }
    kfc_debug("malloc from mem_pool fail. no more spaces");
    return k_null;
}

/* 内部calloc实现 */
static inline void *__kfc_calloc_process(unsigned int target_size)
{
    kmem_node *p_node = k_null;
    if(__check_size_fit_mem_pool(target_size) == 0)
    {
        p_node = __malloc_from_mem_pool(target_size);
    }
    if(k_null == p_node)
    {
        p_node = s_p_malloc(target_size + KFC_NODE_SIZE);
        if(k_null == p_node)
        {
            kfc_error("kfc malloc < %u > fail.", target_size);
            return k_null;
        }else
        {
            __update_mem_occupy(target_size, target_size + KFC_NODE_SIZE, 1);
            kfc_debug("kfc malloc direct < %u > success.", target_size);
        }
    }else
    {
        kfc_debug("kfc malloc from mem_pool < %u > success.", target_size);
    }

    k_memset(p_node, 0, (target_size + KFC_NODE_SIZE));
    KFC_NODE_SET_MEM_SIZE(p_node, target_size);
    return p_node->p_mem;
}

/* 内部free实现 */
static inline void __kfc_free_process(void *p_mem)
{
    kmem_node *p_node = __check_mem_from_mem_pool(p_mem);
    if(k_null == p_node)
    {
        p_node = (kmem_node *)((unsigned long)p_mem - KFC_NODE_SIZE);
        kfc_debug("kfc free direct < %u > success", KFC_NODE_GET_MEM_SIZE(p_node) );
        __update_mem_occupy(KFC_NODE_GET_MEM_SIZE(p_node), KFC_NODE_GET_MEM_SIZE(p_node)+KFC_NODE_SIZE, 0);
        s_p_free(p_node);
    }else
    {
        __free_from_mem_pool(p_node);
        kfc_debug("kfc free from mem_pool < %u > success", KFC_NODE_GET_MEM_SIZE(p_node) );
    }
}

int kfc_init( void *(*sys_malloc)(unsigned int size),
               void (*sys_free)(void *ptr),
               void (*sys_lock)(void),
               void (*sys_unlock)(void)
               )
{
    if( (k_null == sys_malloc) || (k_null == sys_free) || (k_null == sys_lock) || (k_null == sys_unlock) )
    {
        kfc_error("input func is k_null. kfc init fail");
        return -1;
    }

    s_curr_occupy_user = 0;
    s_max_occupy_user = 0;
    s_curr_occupy_all = 0;
    s_max_occupy_all = 0;

    s_p_malloc = sys_malloc;
    s_p_free = sys_free;
    s_p_lock = sys_lock;
    s_p_unlock = sys_unlock;

    k_memset(s_mem_pool_bitmap, 0, KFC_MEM_BITMAP_CNT * sizeof(unsigned int));
    s_p_mem_pool_start = sys_malloc(KFC_MEM_POOL_UNIT_SIZE * KFC_MEM_POOL_UNIT_NUM);
    if(k_null == s_p_mem_pool_start)
    {
        kfc_error("malloc kfc mem_pool fail. hope size:%d", KFC_MEM_POOL_UNIT_SIZE * KFC_MEM_POOL_UNIT_NUM);
        return -2;
    }
    k_memset(s_p_mem_pool_start, 0, KFC_MEM_POOL_UNIT_SIZE * KFC_MEM_POOL_UNIT_NUM);
    s_p_mem_pool_end = s_p_mem_pool_start + KFC_MEM_POOL_UNIT_SIZE * KFC_MEM_POOL_UNIT_NUM;
    kfc_debug("kfc init success");

    return 0;
}

void *kfc_calloc(unsigned int nmemb, unsigned int size)
{
    void *p_result = k_null;
    unsigned int target_size = nmemb * size;
    if(target_size > KFC_MAX_BUF_SIZE)
    {
        kfc_error("input size %u * %u > %u. kfc malloc fails", nmemb, size, KFC_MAX_BUF_SIZE);
        return k_null;
    }
    s_p_lock();
    p_result = __kfc_calloc_process(target_size);
    if(k_null == p_result)
        kfc_error("kfc malloc <%u> fail.", target_size);
    s_p_unlock();
    return p_result;
}

void kfc_free(void *ptr)
{
    if(k_null == ptr)
        return;

    s_p_lock();
    __kfc_free_process(ptr);
    s_p_unlock();
}

/* dump内存池bitmap */
void kfc_dump_mem_pool_bitmaps(void)
{
#define _BIT(value,index) ((value >> index) & 1)

    unsigned int index = 0;
    kfc_debug("--- dump bitmaps begin ---");
    for(index = 0; index < KFC_MEM_BITMAP_CNT; index++)
    {
        unsigned int v = s_mem_pool_bitmap[index];
        kfc_debug("< %3u > 00-15:  %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
                  index, _BIT(v,31), _BIT(v,30), _BIT(v,29), _BIT(v,28), _BIT(v,27), _BIT(v,26), _BIT(v,25), _BIT(v,24),
                  _BIT(v,23), _BIT(v,22), _BIT(v,21), _BIT(v,20), _BIT(v,19), _BIT(v,18), _BIT(v,17), _BIT(v,16) );
        kfc_debug("< %3u > 16-31:  %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
                  index, _BIT(v,15), _BIT(v,14), _BIT(v,13), _BIT(v,12), _BIT(v,11), _BIT(v,10), _BIT(v,9), _BIT(v,8),
                  _BIT(v,7), _BIT(v,6), _BIT(v,5), _BIT(v,4), _BIT(v,3), _BIT(v,2), _BIT(v,1), _BIT(v,0) );
    }
    kfc_debug("--- dump bitmaps end ---");

#undef _BIT
}

/* 统计并返回当前内存使用情况 */
void kfc_update_mem_occupy_status(unsigned int *p_total_bits, unsigned int *p_used_bits,
                                  unsigned int *p_curr_occupy_user, unsigned int *p_max_occupy_user,
                                  unsigned int *p_curr_occupy_all, unsigned int *p_max_occupy_all
                                  )
{
    unsigned int index = 0;
    if( (k_null == p_total_bits) || (k_null == p_used_bits) ||
        (k_null == p_curr_occupy_user) || (k_null == p_max_occupy_user) ||
        (k_null == p_curr_occupy_all)  || (k_null == p_max_occupy_all) )
    {
        kfc_error("input is invalid");
        return;
    }

    *p_total_bits = KFC_MEM_POOL_UNIT_NUM;
    for(index = 0; index < KFC_MEM_BITMAP_CNT; index++)
    {
        int bit_idx = 0;
        unsigned int value = s_mem_pool_bitmap[index];
        for(bit_idx = 0; bit_idx < KFC_INT_BITS_NUM; bit_idx++)
        {
            *p_used_bits += ((value >> bit_idx) & 1);
        }
    }
    *p_curr_occupy_user = s_curr_occupy_user;
    *p_max_occupy_user = s_max_occupy_user;
    *p_curr_occupy_all = s_curr_occupy_all;
    *p_max_occupy_all = s_max_occupy_all;

    kfc_debug("--- mem status update---");
    kfc_debug("total_bits:%u used_bits:%u", *p_total_bits, *p_used_bits);
    kfc_debug("curr_user:%u max_user:%u", *p_curr_occupy_user, *p_max_occupy_user);
    kfc_debug("curr_total:%u max_total:%u", *p_curr_occupy_all, *p_max_occupy_all);



}

/* 内部工具函数测试 */
int test_tool_funcs(void)
{
    int index = 0;
#if 0
    kfc_debug("test __upper_input");
    __upper_input(30);
    __upper_input(31);
    __upper_input(32);
    __upper_input(33);
    __upper_input(34);
    __upper_input(63);
    __upper_input(64);
    __upper_input(65);
    for(index = 0; index < 20; index++)
    {
        __upper_input(index * 5);
    }
#endif
#if 0
    kfc_debug("test __get_free_cnt_in_uint_right");
    __get_free_cnt_in_uint_right( 0x0 );
    __get_free_cnt_in_uint_right( 0x1 );
    __get_free_cnt_in_uint_right( 0xF );
    for(index = 0; index < 20; index++)
    {
        __get_free_cnt_in_uint_right(index);
    }
#endif
#if 0
    kfc_debug("test __get_free_cnt_in_uint_left");
    __get_free_cnt_in_uint_left( 0x0 );
    __get_free_cnt_in_uint_left( 0x1 );
    __get_free_cnt_in_uint_left( 0xFFFFFFFF );
    for(index = 0; index < 20; index++)
    {
        __get_free_cnt_in_uint_left(index * 10);
        __get_free_cnt_in_uint_left(index * 9);
    }
#endif
#if 0
    kfc_debug("test __get_free_bits_idx_in_int_all");
    for(index = 1; index <= 32; index++)
    {
        __get_free_bits_idx_in_int_all(0x0, index);
    }
    for(index = 1; index <= 32; index++)
    {
        __get_free_bits_idx_in_int_all(0xFFFFFFFF, index);
    }

    for(index = 0; index < 10; index++)
    {
        int tmp_idx = 0;
        unsigned input = rand();
        for(tmp_idx = 1; tmp_idx <= 32; tmp_idx++)
        {
            __get_free_bits_idx_in_int_all(input, tmp_idx);
        }
    }
#endif
#if 0
    kfc_debug("test __mark_mem_pool_bitmap");

    dump_mem_pool_bitmaps();
    __mark_mem_pool_bitmap(0, 1, 1);
    dump_mem_pool_bitmaps();
    __mark_mem_pool_bitmap(0, 1, 0);
    dump_mem_pool_bitmaps();

    __mark_mem_pool_bitmap(0, 31, 1);
    dump_mem_pool_bitmaps();
    __mark_mem_pool_bitmap(0, 31, 0);
    dump_mem_pool_bitmaps();

    __mark_mem_pool_bitmap(0, 32, 1);
    dump_mem_pool_bitmaps();
    __mark_mem_pool_bitmap(0, 32, 0);
    dump_mem_pool_bitmaps();

    __mark_mem_pool_bitmap(0, 33, 1);
    dump_mem_pool_bitmaps();
    __mark_mem_pool_bitmap(0, 33, 0);
    dump_mem_pool_bitmaps();

    __mark_mem_pool_bitmap(10, 33, 1);
    dump_mem_pool_bitmaps();
    __mark_mem_pool_bitmap(10, 33, 0);
    dump_mem_pool_bitmaps();

    __mark_mem_pool_bitmap(20, 33, 1);
    dump_mem_pool_bitmaps();
    __mark_mem_pool_bitmap(20, 33, 0);
    dump_mem_pool_bitmaps();
#endif

    return index;
}







