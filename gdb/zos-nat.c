/* z/OS native-dependent code.

   Copyright (C) 2020 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "utils.h"
#include "target.h"
#include "inferior.h"
#include "infrun.h"
#include "inf-child.h"
#include "inf-ptrace.h"
#include "gdbcmd.h"
#include "gdbthread.h"
#include "regset.h"
#include <sys/ptrace.h>
#include "s390-tdep.h"

/* Some ptrace constants that might not have a definition in the
   C library. Values correspond to PT_PSW0 and PT_PSW1 from
   the assembler services manual for USS.  */
#define PTRACE_READ_PSWM	40
#define PTRACE_READ_PSWA	41

/* type of a thread id.  */
typedef uint64_t ztid_t;

/* Annoyingly, we must fetch the low and high halves of each GPR
   separately. Use this type for each of those requests.  */
typedef uint32_t half_gregset_t[16];

/* Maps for register sets.  */

static const struct regcache_map_entry zos_low_gregmap[] =
  {
    { 1, S390_R0_REGNUM, 4 },
    { 1, S390_R1_REGNUM, 4 },
    { 1, S390_R2_REGNUM, 4 },
    { 1, S390_R3_REGNUM, 4 },
    { 1, S390_R4_REGNUM, 4 },
    { 1, S390_R5_REGNUM, 4 },
    { 1, S390_R6_REGNUM, 4 },
    { 1, S390_R7_REGNUM, 4 },
    { 1, S390_R8_REGNUM, 4 },
    { 1, S390_R9_REGNUM, 4 },
    { 1, S390_R10_REGNUM, 4 },
    { 1, S390_R11_REGNUM, 4 },
    { 1, S390_R12_REGNUM, 4 },
    { 1, S390_R13_REGNUM, 4 },
    { 1, S390_R14_REGNUM, 4 },
    { 1, S390_R15_REGNUM, 4 },
    { 0 }
  };

static const struct regcache_map_entry zos_high_gregmap[] =
  {
    { 1, S390_R0_UPPER_REGNUM, 4 },
    { 1, S390_R1_UPPER_REGNUM, 4 },
    { 1, S390_R2_UPPER_REGNUM, 4 },
    { 1, S390_R3_UPPER_REGNUM, 4 },
    { 1, S390_R4_UPPER_REGNUM, 4 },
    { 1, S390_R5_UPPER_REGNUM, 4 },
    { 1, S390_R6_UPPER_REGNUM, 4 },
    { 1, S390_R7_UPPER_REGNUM, 4 },
    { 1, S390_R8_UPPER_REGNUM, 4 },
    { 1, S390_R9_UPPER_REGNUM, 4 },
    { 1, S390_R10_UPPER_REGNUM, 4 },
    { 1, S390_R11_UPPER_REGNUM, 4 },
    { 1, S390_R12_UPPER_REGNUM, 4 },
    { 1, S390_R13_UPPER_REGNUM, 4 },
    { 1, S390_R14_UPPER_REGNUM, 4 },
    { 1, S390_R15_UPPER_REGNUM, 4 },
    { 0 }
  };

static const struct regset zos_low_gregset =
  {
    zos_low_gregmap,
    regcache_supply_regset,
    regcache_collect_regset
  };

static const struct regset zos_high_gregset =
  {
    zos_high_gregmap,
    regcache_supply_regset,
    regcache_collect_regset
  };

/* Return if the register is either a GPR or a register we can get
   while we are getting the GPRs.  */

static bool
gpr_regnum_p (int regnum)
{
  /* Should be gprs, pswa, pswm, and CRs.  */
  return ((regnum >= S390_R0_REGNUM && regnum <= S390_R15_REGNUM)
	  || (regnum >= S390_R0_UPPER_REGNUM
	      && regnum <= S390_R15_UPPER_REGNUM)
	  || regnum == S390_PSWM_REGNUM
	  || regnum == S390_PSWA_REGNUM);
}

/* Wrapper for ptrace that handles EAGAIN, becaues apparently z/OS ptrace
   can actually fail with it for some reason.  */

template <typename ...Args>
long
ptrace_retry (enum __ptrace_request req, Args... args)
{
  long ret;

  errno = 0;
  do
    {
      ret = ptrace (req, std::forward<Args> (args)...);
    }
  while (errno == EAGAIN);

  return ret;
};

class zos_nat_target final : public inf_ptrace_target
{
public:
  enum target_xfer_status xfer_partial (enum target_object object,
					const char *annex,
					gdb_byte *readbuf,
					const gdb_byte *writebuf,
					ULONGEST offset, ULONGEST len,
					ULONGEST *xfered_len) override;

  /* Add our register access methods.  */
  void fetch_registers (struct regcache *, int) override;
  void store_registers (struct regcache *, int) override;

  /* We override it so we can store the thread id immediately.  */
  ptid_t wait (ptid_t, struct target_waitstatus *, int) override;
};

static zos_nat_target the_zos_nat_target;

static unsigned int debug_zos_nat;
static void
show_debug_zos_nat (struct ui_file *file, int from_tty,
		    struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("Debugging of z/OS native target is %s.\n"),
		    value);
}

/* Read and return the current focus thread.  */
static ztid_t
get_focus_thread (void)
{
  ztid_t tid;
  if (ptrace_retry (PT_THREAD_READ_FOCUS,
		    inferior_ptid.pid (), &tid, 0L, 0L) < 0)
    perror_with_name ("ptrace PT_THREAD_READ_FOCUS");
  return tid;
}

ptid_t
zos_nat_target::wait (ptid_t ptid, struct target_waitstatus *ourstatus,
		      int target_options)
{
  ptid_t wptid;

  if (debug_zos_nat)
    {
      char *options_string;

      options_string = target_options_to_string (target_options);
      fprintf_unfiltered (gdb_stdlog,
			  "zos_nat_wait: [%s], [%s]\n",
			  target_pid_to_str (ptid),
			  options_string);
      xfree (options_string);
    }

  while (1)
    {
      /* wait, only break out for events of interest.  */
      wptid = inf_ptrace_target::wait (ptid, ourstatus, target_options);

      if (debug_zos_nat)
	{
	  fprintf_unfiltered (gdb_stdlog,
			      "zos_nat_wait: stop for %u\n",
			      wptid.pid ());
	}

      /* z/OS TODO: handle error.  */

      if (ourstatus->kind == TARGET_WAITKIND_STOPPED)
	{
	  /* z/OS TODO: This is insufficient, because on exec tid may
	     change. We should do a PT_THREAD_INFO and sync internal
	     gdb info with returned thread info. Prune nonexistent
	     threads (preferably with some notification mechanism for
	     anything waiting on an event from a specific thread) and
	     add new threads (treat it like an attach). */
	  if (0)
	    {
	      /* Now that the process is stopped, we can use ptrace.  */
	      wptid = ptid_t (wptid.pid (), 0, get_focus_thread ());

	      /* We need to check the special case where we are waiting
		 on the exec in a newly forked inferior.  */
	      if (inferior_ptid.is_pid ())
		thread_change_ptid (inferior_ptid, wptid);
	    }
	}

      break;
    }

  return wptid;
}

/* Get info about the primary load module.  */

CORE_ADDR
zos_get_load_addr (void)
{
  struct __ptrace_ldinfo *info;
  int ret;
  pid_t pid = inferior_ptid.pid ();
  size_t bufsz = sizeof (struct __ptrace_ldinfo);
  const size_t maxbuf = 64000;	/* OS-imposed max.  */
  CORE_ADDR origin;

  if (debug_zos_nat)
    fprintf_unfiltered (gdb_stdlog, "Getting load module info for %d\n",
			pid);

  if (!pid)
    warning ("zos_get_load_addr called without inferior");

  /* We're doing low-level stuff, so just deal with explicit malloc.  */
  info = static_cast<struct __ptrace_ldinfo *>(xmalloc (bufsz));
  /* No exceptions permitted between here and xfree.  */

  while (true)
    {
      /* Retry until the buffer is large enough.  */
      ret = ptrace_retry (PT_LDINFO, pid, info, bufsz, 0L);
      if (ret == 0 || bufsz == maxbuf)
	break;
      bufsz = std::min (bufsz * 4, maxbuf);
      info = static_cast<struct __ptrace_ldinfo *>(xrealloc (info,
							     bufsz));
    }

  if (ret != 0)
    perror_with_name (_("Couldn't get get load info"));

  origin = info->text_origin;
  xfree (info);
  /* z/OS TODO: Is the initial load module always the first load module?  */

  return origin;
}

/* Generate a fake auxv for the inferior and xfer it.  */

static enum target_xfer_status
xfer_fake_auxv (gdb_byte *readbuf,
		const gdb_byte *writebuf,
		ULONGEST offset,
		ULONGEST len, ULONGEST *xfered_len)
{
  /* z/OS TODO: this.  */
  warning (_("TARGET_OBJECT_AUXV not yet implmented for z/OS"));
  return TARGET_XFER_UNAVAILABLE;
}

/* Implement the "xfer_partial" target_ops method.  */

enum target_xfer_status
zos_nat_target::xfer_partial (enum target_object object,
			      const char *annex, gdb_byte *readbuf,
			      const gdb_byte *writebuf,
			      ULONGEST offset, ULONGEST len,
			      ULONGEST *xfered_len)
{
  switch (object)
    {
    case TARGET_OBJECT_AUXV:
      /* Because so many things expect us to have a real auxv,
	 we just fake one. We either do this or rewrite parts of
	 solib-svr4.c that use the auxv to use a more generic
	 interface.  */
      /* z/OS TODO: This. Know that this will be used via
	 target_auxv_search. At the very least, we need AT_ENTRY to
	 work for svr4 executable symbol relocation to work right.
         Might need AT_PHDR, AT_PHENT, AT_PHNUM, AT_BASE, AT_ENTRY,
         and AT_HWCAP.  */
      return xfer_fake_auxv (readbuf, writebuf, offset, len, xfered_len);

    case TARGET_OBJECT_SIGNAL_INFO:
      warning (_("TARGET_OBJECT_SIGNAL_INFO not yet implmented for z/OS"));
      return TARGET_XFER_UNAVAILABLE;

    case TARGET_OBJECT_MEMORY:
      warning (_("TARGET_OBJECT_MEMORY not yet implmented for z/OS"));
      return TARGET_XFER_UNAVAILABLE;

    default:
      return inf_ptrace_target::xfer_partial (object, annex, readbuf,
					      writebuf, offset, len,
					      xfered_len);
    }

}

/* Fetch all general-purpose registers from process TID and
   store their values in GDB's register cache.  */

static void
fetch_regs (struct regcache *regcache, int tid)
{
  half_gregset_t half_regs;
  uint32_t val;
  gdb_byte buf[4];
  enum bfd_endian byte_order = gdbarch_byte_order (regcache->arch ());

  /* z/OS TODO: Eventually, we should use a PT_READ_GPR blockreq to
     fetch all this info at once.  */

  if (ptrace_retry (PT_REGSET, tid, &half_regs, 0L, 0L) < 0)
    perror_with_name (_("Couldn't get register low halves"));

  regcache_supply_regset (&zos_low_gregset, regcache, -1, &half_regs,
			  sizeof (half_regs));

  if (ptrace_retry (PT_REGHSET, tid, &half_regs, 0L, 0L) < 0)
    perror_with_name (_("Couldn't get register high halves"));

  regcache_supply_regset (&zos_high_gregset, regcache, -1, &half_regs,
			  sizeof (half_regs));

  /* Only way to know if an error occurred for these is to check
     errno.  */
  errno = 0;
  val = static_cast<uint32_t>(ptrace_retry (PT_READ_GPR, tid,
					    PTRACE_READ_PSWM, 0L, 0L));
  if (errno != 0)
    perror_with_name ("Couldn't get pswm");

  store_unsigned_integer (buf, 4, byte_order, val);
  regcache->raw_supply (S390_PSWM_REGNUM, buf);

  errno = 0;
  val = static_cast<uint32_t>(ptrace_retry (PT_READ_GPR, tid,
					    PTRACE_READ_PSWA, 0L, 0L));
  if (errno != 0)
    perror_with_name ("Couldn't get pswa");

  store_unsigned_integer (buf, 4, byte_order, val);
  regcache->raw_supply (S390_PSWA_REGNUM, buf);
}

/* Fetch register REGNUM from the child process.  If REGNUM is -1, do
   this for all registers.  */

void
zos_nat_target::fetch_registers (struct regcache *regcache, int regnum)
{
  pid_t tid = get_ptrace_pid (regcache->ptid ());

  /* z/OS TODO: Special case -1 into one big blockreq.  */

  if (regnum == -1 || gpr_regnum_p (regnum))
    fetch_regs (regcache, tid);

  /* z/OS TODO: All the rest.  */
}

/* Store register REGNUM back into the child process.  If REGNUM is
   -1, do this for all registers.  */

void
zos_nat_target::store_registers (struct regcache *regcache, int regnum)
{
  /* TODO.  */
}

void
_initialize_zos_nat (void)
{
  /* Register the target.  */
  add_inf_child_target (&the_zos_nat_target);

  add_setshow_zuinteger_cmd ("zos", class_maintenance,
			     &debug_zos_nat, _("\
Set debugging of z/OS native target."), _("\
Show debugging of z/OS native target."), _("\
Enables printf debugging output."),
			     NULL,
			     show_debug_zos_nat,
			     &setdebuglist, &showdebuglist);
}
