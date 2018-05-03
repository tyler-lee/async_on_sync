#ifndef __USER_TYPES_H__
#define __USER_TYPES_H__

/* User defined types */
#define CORES_PER_CPU 4
//extern const int CORES_PER_CPU;
#define CORES_MASK ((1 << CORES_PER_CPU) - 1)
//extern const int CORES_MASK;

#ifndef unlikely
#define unlikely(expr) __builtin_expect (expr, 0)
#endif
#ifndef likely
#define likely(expr)   __builtin_expect (expr, 1)

#endif

#define LOOPS_PER_THREAD 500

#endif //!__USER_TYPES_H__
