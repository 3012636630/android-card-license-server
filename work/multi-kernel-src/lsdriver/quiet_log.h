#ifndef LSDRIVER_QUIET_LOG_H
#define LSDRIVER_QUIET_LOG_H

/* Release builds keep kernel logging silent so format strings and runtime
 * messages do not become an application-visible fingerprint.  Define
 * LS_VERBOSE_LOG only for local bring-up builds. */
#ifdef LS_VERBOSE_LOG
#define LS_PRINTK(...)  printk(__VA_ARGS__)
#define LS_PR_INFO(...) pr_info(__VA_ARGS__)
#define LS_PR_ERR(...)  pr_err(__VA_ARGS__)
#define LS_PR_WARN(...) pr_warn(__VA_ARGS__)
#define LS_PR_DEBUG(...) pr_debug(__VA_ARGS__)
#else
#define LS_PRINTK(...)  do { } while (0)
#define LS_PR_INFO(...) do { } while (0)
#define LS_PR_ERR(...)  do { } while (0)
#define LS_PR_WARN(...) do { } while (0)
#define LS_PR_DEBUG(...) do { } while (0)
#endif

#endif
