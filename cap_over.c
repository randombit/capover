/*
 *  (C) 2003-2004 Jack Lloyd (lloyd@randombit.net)
 *     With various bits blatantly stolen from capability.c, root_plug.c,
 *     and a few other places.
 *
 *  Capability overriding LSM for Linux 2.6, version 0.9.3
 *      http://www.randombit.net/projects/cap_over/
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/binfmts.h>
#include <linux/rwsem.h>

/* Should be in include/linux/sysctl.h; want to be non-invasive */
#define KERN_CAP_OVER 100 /* FRAGILE; 2.6.8 max is 65 */

/********************* CONFIGURATION STUFF *********************/
/* Mode of /proc/sys/kernel/cap_over/xxx */
#define PROC_MODE 0644

/* The longest path for a binary we'll take; assumes this will fit on the
 * stack, so don't use more than 512 (else we risk overflowing printk's
 * buffer). Default is probably OK as mostly we're looking for stuff in
 * {/usr,}/{bin,sbin}, so it should be pretty short. The default gives us
 * plenty of space even for weird paths.
 */
#define EXE_PATH_MAX 64

/* The biggest policy string we'll take. This is kmalloc'ed, so you can make it
 * bigger if you want. You would have to have some *seriously* crazy rules to
 * exceed the default, though.
 */
#define INPUT_SIZE 4096
/********************* END CONFIGURATION STUFF *********************/

/* identification */
#define LONG_NAME "CapOver LSM (cap_over)"
#define VERSION "0.9.3"

#if defined(CONFIG_SECURITY_CAP_OVER_MODULE)
  #define MY_NAME THIS_MODULE->name
#else
  #define MY_NAME "cap_over"
#endif

/* There are extras, that's OK (only wasting 4 slots as of 2.6.0) */
#define MAX_CAP 8*sizeof(kernel_cap_t)

/*************************************************
* A list of who gets extra permissions           *
*************************************************/
struct ruleset
   {
   int uid, gid;      /* the uid/gid, or -1 for unused */
   int audit;         /* if true, print a message when this rule is used */
   char* path;        /* the path, or NULL for unused */

   struct ruleset* next; /* next rule */
   };

static struct ruleset* our_rulesets[MAX_CAP];
static DECLARE_RWSEM(ruleset_sem); /* global lock on the rulesets */

/*************************************************
* CAP_x -> name (for audit logs)                 *
*************************************************/
static char* CAP_NAMES[MAX_CAP];

#define SET_CAP_NAME(index, name)                                      \
   do {                                                                \
      if(index < MAX_CAP)                                              \
         CAP_NAMES[index] = name;                                      \
      else                                                             \
          printk(KERN_ERR "Tried to set cap %d to %s\n", index, name); \
   } while(0)

static void init_cap_names(void)
   {
   int j;

   /* I suppose we could kmalloc all of the strings, give the unknown ones a
      string of "(unknown %d)", and free them on module close, but it's just
      way more effort than it's worth.
   */
   for(j = 0; j != MAX_CAP; j++)
      CAP_NAMES[j] = "(unknown capability)";

   SET_CAP_NAME(CAP_CHOWN, "CAP_CHOWN");
   SET_CAP_NAME(CAP_DAC_OVERRIDE, "CAP_DAC_OVERRIDE");
   SET_CAP_NAME(CAP_DAC_READ_SEARCH, "CAP_DAC_READ_SEARCH");
   SET_CAP_NAME(CAP_FOWNER, "CAP_FOWNER");
   SET_CAP_NAME(CAP_FSETID, "CAP_FSETID");
   SET_CAP_NAME(CAP_KILL, "CAP_KILL");
   SET_CAP_NAME(CAP_SETGID, "CAP_SETGID");
   SET_CAP_NAME(CAP_SETUID, "CAP_SETUID");
   SET_CAP_NAME(CAP_SETPCAP, "CAP_SETPCAP");
   SET_CAP_NAME(CAP_LINUX_IMMUTABLE, "CAP_LINUX_IMMUTABLE");
   SET_CAP_NAME(CAP_NET_BIND_SERVICE, "CAP_NET_BIND_SERVICE");
   SET_CAP_NAME(CAP_NET_BROADCAST, "CAP_NET_BROADCAST");
   SET_CAP_NAME(CAP_NET_ADMIN, "CAP_NET_ADMIN");
   SET_CAP_NAME(CAP_NET_RAW, "CAP_NET_RAW");
   SET_CAP_NAME(CAP_IPC_LOCK, "CAP_IPC_LOCK");
   SET_CAP_NAME(CAP_IPC_OWNER, "CAP_IPC_OWNER");
   SET_CAP_NAME(CAP_SYS_MODULE, "CAP_SYS_MODULE");
   SET_CAP_NAME(CAP_SYS_RAWIO, "CAP_SYS_RAWIO");
   SET_CAP_NAME(CAP_SYS_CHROOT, "CAP_SYS_CHROOT");
   SET_CAP_NAME(CAP_SYS_PTRACE, "CAP_SYS_PTRACE");
   SET_CAP_NAME(CAP_SYS_PACCT, "CAP_SYS_PACCT");
   SET_CAP_NAME(CAP_SYS_ADMIN, "CAP_SYS_ADMIN");
   SET_CAP_NAME(CAP_SYS_BOOT, "CAP_SYS_BOOT");
   SET_CAP_NAME(CAP_SYS_NICE, "CAP_SYS_NICE");
   SET_CAP_NAME(CAP_SYS_RESOURCE, "CAP_SYS_RESOURCE");
   SET_CAP_NAME(CAP_SYS_TIME, "CAP_SYS_TIME");
   SET_CAP_NAME(CAP_SYS_TTY_CONFIG, "CAP_SYS_TTY_CONFIG");
   SET_CAP_NAME(CAP_MKNOD, "CAP_MKNOD");
   SET_CAP_NAME(CAP_LEASE, "CAP_LEASE");
   }

/*************************************************
* Produce an audit log message                   *
*************************************************/
static void capover_audit(int audit_level, int cap, const char* program,
                          uid_t uid, uid_t euid, gid_t gid, gid_t egid)
   {
   if(audit_level == 0)
      return;

   /* FIXME: ratelimit. audit_level > 2 might mean increasing audit priority,
      ie less likely to be dropped
   */

   if(uid == euid && gid == egid)
      {
      printk(KERN_NOTICE "Audit (%s): Giving %s (%d) to %s (uid=%d, gid=%d)\n",
             MY_NAME, CAP_NAMES[cap], cap, program, uid, gid);
      }
   else
      {
      printk(KERN_NOTICE "Audit (%s): Giving %s (%d) to %s "
                         "(uid=%d, euid=%d, gid=%d, egid=%d)\n",
             MY_NAME, CAP_NAMES[cap], cap, program, uid, euid, gid, egid);
      }
   }

/*************************************************
* Possibly modify the capset                     *
*************************************************/
static int cap_over_bprm_set_security(struct linux_binprm* bprm)
   {
   char buf[EXE_PATH_MAX] = { 0 };
   const char* bin_path = NULL;
   int j, err;

   /* first do whatever commoncap.c thinks is good */
   err = cap_bprm_set_security(bprm);
   if(err)
      return err;

   /* No way am I going to walk into the minefield that is interpreted
      programs with privs.
   */
   if(bprm->sh_bang)
      return 0;

   /* bprm->filename doesn't always work (relative paths and so on will show
      up). We do this outside the loop so we don't keep calling d_path again
      and again with the same arguments.
   */
   bin_path = d_path(bprm->file->f_dentry, bprm->file->f_vfsmnt,
                     buf, sizeof(buf));

   /* NOTE: it's OK if bin_path is NULL as long as the rule isn't path based
      (we just ignore it). If we come to a rule that checks the path, and we
      don't have it, we just assume the rule isn't true.
        FIXME: Should we print a warning here?
        FIXME: Should we see if bprm->filename if d_path fails?
   */
   if(IS_ERR(bin_path))
      bin_path = NULL;

   down_read(&ruleset_sem);
   /* see if this process gets any more capabilities */
   for(j = 0; j != MAX_CAP; j++)
      {
      struct ruleset* this_rule = our_rulesets[j];

      /* it's already got the cap (either it's root, or they added support for
       * capabilities in the VFS). Skip tests for this cap.
       */
      if(cap_raised(bprm->cap_effective, j) ||
         cap_raised(bprm->cap_inheritable, j) ||
         cap_raised(bprm->cap_permitted, j))
         {
         continue;
         }

      while(this_rule)
         {
         const int cap_uid = this_rule->uid;
         const int cap_gid = this_rule->gid;

         const uid_t real_uid = current->uid;
         const gid_t real_gid = current->gid;

         int ok = 1; /* should we give it the cap? */

         /* Sanity check */
         if(cap_uid == -1 && cap_gid == -1 && !this_rule->path)
            {
            printk(KERN_WARNING "%s: got null perm set for %s (%d)\n",
                   MY_NAME, CAP_NAMES[j], j);
            ok = 0;
            }

         if(ok && cap_uid != -1 && cap_uid != bprm->e_uid &&
            cap_uid != real_uid)
            ok = 0;

         if(ok && cap_gid != -1 && cap_gid != bprm->e_gid &&
            cap_gid != real_gid)
            ok = 0;

         if(ok && this_rule->path)
            {
            if(!bin_path)
               ok = 0; /* path check, and no filename. bad kernel, no cap! */

            if(ok && (strcmp(this_rule->path, bin_path) != 0))
               ok = 0; /* this is not the path you are looking for... */
            }

         if(ok) /* OK, give it the cap */
            {
            /* FIXME: control which set(s) get raised through the policy */
            cap_raise(bprm->cap_effective, j);
            cap_raise(bprm->cap_permitted, j);
            cap_raise(bprm->cap_inheritable, j);

            capover_audit(this_rule->audit, j, bin_path,
                          real_uid, bprm->e_uid, real_gid, bprm->e_gid);

            break; /* go to next cap */
            }

         this_rule = this_rule->next; /* check next rule */
         }
      }
   up_read(&ruleset_sem);

   return 0;
   }

static struct security_operations cap_over_security_ops = {
   /* Use the commoncap.c versions for everything except set_security() */
   .ptrace =                    cap_ptrace,
   .capget =                    cap_capget,
   .capset_check =              cap_capset_check,
   .capset_set =                cap_capset_set,
   .capable =                   cap_capable,
   .netlink_send =              cap_netlink_send,
   .netlink_recv =              cap_netlink_recv,

   .bprm_apply_creds =          cap_bprm_apply_creds,
   .bprm_set_security =         cap_over_bprm_set_security,
   .bprm_secureexec =           cap_bprm_secureexec,

   .inode_setxattr =            cap_inode_setxattr,
   .inode_removexattr =         cap_inode_removexattr,

   .task_post_setuid =          cap_task_post_setuid,
   .task_reparent_to_init =     cap_task_reparent_to_init,

   .syslog =                    cap_syslog,

   .vm_enough_memory =          cap_vm_enough_memory,
};

/*************************************************
* Register the security module                   *
*************************************************/
static int secondary;

static int do_register_security(void)
   {
   /* register ourselves with the security framework */
   if(register_security(&cap_over_security_ops))
      {
      printk(KERN_INFO "Failure registering " LONG_NAME " with the kernel\n");
      /* try registering with primary module */
      if(mod_reg_security(MY_NAME, &cap_over_security_ops))
         {
         printk(KERN_INFO "Failure registering " LONG_NAME
                          " with primary security module.\n");
         return -EINVAL;
         }
      secondary = 1;
      }
   return 0;
   }

/*************************************************
* Unregister the security module                 *
*************************************************/
static void do_unregister_security(void)
   {
   if(secondary)
      {
      if(mod_unreg_security(MY_NAME, &cap_over_security_ops))
         printk(KERN_INFO "Failure unregistering " LONG_NAME
                " with primary module.\n");
      }
   else if(unregister_security(&cap_over_security_ops))
      printk(KERN_INFO "Failure unregistering " LONG_NAME
                       " with the kernel\n");
   }

/*************************************************
* Add a rule                                     *
*   Called with ruleset_sem set for writing      *
*************************************************/
static int add_rule(int cap, int audit, int uid, int gid, char* path)
   {
   struct ruleset* new_rule = NULL;

   if(uid == -1 && gid == -1 && path == NULL)
      return -EINVAL; /* a rule that's always true */

   new_rule = kmalloc(sizeof(struct ruleset), GFP_KERNEL);
   if(!new_rule)
      return -ENOMEM;

   new_rule->uid = uid;
   new_rule->gid = gid;
   new_rule->path = path;
   new_rule->audit = 1;
   new_rule->next = NULL;

   /* In the future, audit 2...N may mean something that audit == 1 doesn't.
      If it's something we don't recognize, then just assume auditing is on.
   */
   if(audit == 0 || audit == 1)
      new_rule->audit = audit;

   if(our_rulesets[cap] == NULL)
      our_rulesets[cap] = new_rule;
   else
      {
      struct ruleset* walker = our_rulesets[cap];
      while(walker->next)
         walker = walker->next;
      walker->next = new_rule;
      }
   return 0;
   }

/*************************************************
* Free the ruleset                               *
*   Called with ruleset_sem set for writing      *
*************************************************/
static void free_ruleset(struct ruleset* ruleset)
   {
   while(ruleset)
      {
      struct ruleset* next = ruleset->next;

      if(ruleset->path)
         kfree(ruleset->path);
      kfree(ruleset);

      ruleset = next;
      }
   }

/*************************************************
* Read the option string, (try to) parse it      *
*   Called with ruleset_sem set for writing      *
*************************************************/
static int parse_settings(const char* options, struct ruleset** ruleset)
   {
   int uid = -1, gid = -1, audit = 1;
   char* path = NULL;
   const char* p = options;
   int cap;

   if(!options || !ruleset)
      return -EINVAL;

   cap = ruleset - our_rulesets;

   /* Something is *seriously* wrong if this happens */
   if(cap < 0 || cap >= MAX_CAP)
      {
      printk(KERN_WARNING "%s: parse_settings says %d\n", MY_NAME, cap);
      printk(KERN_WARNING "   (remove module and contact maintainer)\n");
      return -EINVAL;
      }

   /* remove the old settings */
   free_ruleset(our_rulesets[cap]);
   our_rulesets[cap] = NULL;

   while(*p)
      {
      char type = *p;
      p++;

      if(type == 'a')
         {
         char value = *p++;

         /* if it's not exactly 0, then audit is on */
         audit = 1;

         if(value == '0') audit = 0;
         if(value == '1') audit = 1;
         }
      else if(type == 'u' || type == 'g')
         {
         int value = 0;
         size_t j;

         if(type == 'u' && uid != -1)
            return -EINVAL;
         if(type == 'g' && gid != -1)
            return -EINVAL;

         for(j = 0; j != 4; j++)
            {
            unsigned char bits = 0;
            char next = *p++;

            if(next == 0)
               return -EINVAL;

            if(!isxdigit(next))
               return -EINVAL;

            /* assumes ASCII (probably OK in Linux) */
            if(next >= 'A' && next <= 'F') bits = next - 'A' + 10;
            else if(next >= 'a' && next <= 'f') bits = next - 'a' + 10;
            else if(next >= '0' && next <= '9') bits = next - '0';

            value = (value << 4) | bits;
            }

         if(type == 'u')
            uid = value;
         else
            gid = value;
         }
      else if(type == 'p')
         {
         char buf[EXE_PATH_MAX] = { 0 };
         size_t j = 0;

         /* The policy compiler should prevent this anyway */
         if(*p != '/')
            {
            printk(KERN_WARNING "%s: Cannot use relative paths\n", MY_NAME);
            return -EINVAL;
            }

         while(*p && *p != '_')
            {
            if(j >= sizeof(buf) - 1)
               return -ENOMEM;
            buf[j++] = *p++;
            }

         path = kmalloc(j + 1, GFP_KERNEL);
         strcpy(path, buf);
         }
      else if(type == '_')
         {
         int err = add_rule(cap, audit, uid, gid, path);
         if(err)
            return err;

         /* reset everything */
         uid = gid = -1;
         audit = 1;
         path = NULL;
         }
      else
         return -EINVAL;
      }

   if(uid != -1 || gid != -1 || path)
      {
      int err = add_rule(cap, audit, uid, gid, path);
      if(err)
         return err;
      }

   return 0;
   }

/*************************************************
* Turn our internal bits into a string           *
*   Called with ruleset_sem set for reading      *
*************************************************/
static int format_output(struct ruleset* ruleset, ctl_table* outtable)
   {
   char* outbuf = outtable->data;
   int maxlen = outtable->maxlen - 1;
   int pos = 0;

   while(ruleset)
      {
      pos += snprintf(outbuf + pos, maxlen - pos, "a%d", ruleset->audit);

      if(ruleset->uid != -1)
         pos += snprintf(outbuf + pos, maxlen - pos, "u%04X", ruleset->uid);
      if(ruleset->gid != -1)
         pos += snprintf(outbuf + pos, maxlen - pos, "g%04X", ruleset->gid);
      if(ruleset->path)
         pos += snprintf(outbuf + pos, maxlen - pos, "p%s", ruleset->path);

      if((ruleset->uid != -1 || ruleset->gid != -1 || ruleset->path) &&
         (ruleset->next))
         pos += snprintf(outbuf + pos, maxlen - pos, "_");

      ruleset = ruleset->next;
      }

   if(pos >= maxlen - 1)
      return -E2BIG;

   return 0;
   }

/*************************************************
* Handle a /proc input or output                 *
*************************************************/
static int cap_over_proc_handler(ctl_table* ctl, int write,
                                 struct file* filep,
                                 void __user * buffer, size_t* lenp,
                                 loff_t* offsetp)
   {
   struct ruleset** ruleset = ctl->data;
   int err;
   ctl_table fake_table; /* neat hack from drivers/char/random.c */

   if(!ruleset || !lenp || !buffer || !filep || !offsetp)
      return 0;

   fake_table.data = kmalloc(INPUT_SIZE, GFP_KERNEL);
   memset(fake_table.data, 0, INPUT_SIZE);
   fake_table.maxlen = INPUT_SIZE;

   if(write)
      {
      err = proc_dostring(&fake_table, 1, filep, buffer, lenp, offsetp);
      if(!err)
         {
         down_write(&ruleset_sem);
         err = parse_settings(fake_table.data, ruleset);

         /* If we got an error in parse, free any structures we allocated */
         if(err)
            {
            free_ruleset(*ruleset);
            *ruleset = NULL;
            }

         up_write(&ruleset_sem);
         }
      }
   else
      {
      down_read(&ruleset_sem);
      err = format_output(*ruleset, &fake_table);
      up_read(&ruleset_sem);
      if(!err)
         err = proc_dostring(&fake_table, 0, filep, buffer, lenp, offsetp);
      }

   kfree(fake_table.data);

   return err;
   }

/*************************************************
* Define the /proc structures                    *
*************************************************/
#define CAP_ENTRY(str_name, cap_type)            \
   {                                             \
      .ctl_name     = cap_type + 1,              \
      .procname     = str_name,                  \
      .mode         = PROC_MODE,                 \
      .proc_handler = cap_over_proc_handler,     \
      .data         = our_rulesets + cap_type,   \
   }

static ctl_table cap_over_table[] = {
   CAP_ENTRY("chown", CAP_CHOWN),
   CAP_ENTRY("dac_override", CAP_DAC_OVERRIDE),
   CAP_ENTRY("dac_read_search", CAP_DAC_READ_SEARCH),
   CAP_ENTRY("fowner", CAP_FOWNER),
   CAP_ENTRY("fsetid", CAP_FSETID),
   CAP_ENTRY("kill", CAP_KILL),
   CAP_ENTRY("setgid", CAP_SETGID),
   CAP_ENTRY("setuid", CAP_SETUID),
   CAP_ENTRY("fs_immutable", CAP_LINUX_IMMUTABLE),
   CAP_ENTRY("net_bind", CAP_NET_BIND_SERVICE),
   CAP_ENTRY("net_broadcast", CAP_NET_BROADCAST),
   CAP_ENTRY("net_admin", CAP_NET_ADMIN),
   CAP_ENTRY("net_raw", CAP_NET_RAW),
   CAP_ENTRY("ipc_lock", CAP_IPC_LOCK),
   CAP_ENTRY("ipc_owner", CAP_IPC_OWNER),
   CAP_ENTRY("sys_module", CAP_SYS_MODULE),
   CAP_ENTRY("sys_rawio", CAP_SYS_RAWIO),
   CAP_ENTRY("sys_chroot", CAP_SYS_CHROOT),
   CAP_ENTRY("sys_ptrace", CAP_SYS_PTRACE),
   CAP_ENTRY("sys_pacct", CAP_SYS_PACCT),
   CAP_ENTRY("sys_admin", CAP_SYS_ADMIN),
   CAP_ENTRY("sys_boot", CAP_SYS_BOOT),
   CAP_ENTRY("sys_nice", CAP_SYS_NICE),
   CAP_ENTRY("sys_resource", CAP_SYS_RESOURCE),
   CAP_ENTRY("sys_time", CAP_SYS_TIME),
   CAP_ENTRY("sys_tty_config", CAP_SYS_TTY_CONFIG),
   CAP_ENTRY("mknod", CAP_MKNOD),
   CAP_ENTRY("lease", CAP_LEASE),
   { .ctl_name = 0 }
};

static ctl_table cap_over_dir_table[] = {
   {
      .ctl_name = KERN_CAP_OVER,
      .procname = "cap_over",
      .maxlen   = 0,
      .mode     = 0555,
      .child    = cap_over_table,
   },
   { .ctl_name = 0 }
};

static ctl_table cap_over_root_table[] = {
   {
      .ctl_name = CTL_KERN,
      .procname = "kernel",
      .maxlen   = 0,
      .mode     = 0555,
      .child    = cap_over_dir_table,
   },
   { .ctl_name = 0 }
};

static struct ctl_table_header* sysctl_root_table = NULL;

/*************************************************
* Initialize the module                          *
*************************************************/
static int __init cap_over_init(void)
   {
   int err = do_register_security();
   if(err)
      return err;

   sysctl_root_table = register_sysctl_table(cap_over_root_table, 0);
   if(!sysctl_root_table)
      {
      printk(KERN_WARNING
             "Sysctl registration failed, aborting LSM initialization\n");
      do_unregister_security();
      return -ENOMEM;
      }

   /* FIXME: set sysctl owner to THIS_MODULE (right?) */

   init_cap_names();

   printk(KERN_INFO LONG_NAME ", version " VERSION ", loaded\n");
   return 0;
   }

/*************************************************
* Shutdown the module                            *
*************************************************/
static void __exit cap_over_exit(void)
   {
   int j;

   /* Keep the lock until we're all the way done */
   down_write(&ruleset_sem);

   for(j = 0; j != MAX_CAP; j++)
      {
      free_ruleset(our_rulesets[j]);
      our_rulesets[j] = NULL;
      }

   do_unregister_security();

   unregister_sysctl_table(sysctl_root_table);
   sysctl_root_table = NULL;

   up_write(&ruleset_sem);

   printk(KERN_INFO LONG_NAME ", version " VERSION ", removed\n");
   }

security_initcall(cap_over_init);
module_exit(cap_over_exit);

MODULE_DESCRIPTION("Give a process extra capabilities based on uid/gid/path");
MODULE_AUTHOR("Jack Lloyd <lloyd@randombit.net>");
MODULE_LICENSE("GPL");
