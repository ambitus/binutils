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
#include "elf/external.h"
#include "elf/common.h"

/* Some ptrace constants that might not have a definition in the
   C library. PSW constants correspond to PT_PSW0 and PT_PSW1 from
   the assembler services manual for USS.  */
#define PTRACE_REG_PSWM		40
#define PTRACE_REG_PSWA		41
#define PTRACE_REG_GPRL0	0
#define PTRACE_REG_GPRL15	15
#define PTRACE_REG_GPRH0	58
#define PTRACE_REG_GPRH15	73

/* The OS limits most requests dealing with buffers to a fixed maximum
   size per operation.  */
#define PTRACE_BUFF_SIZE_MAX	64000

/* type of a thread id.  */
typedef uint64_t ztid_t;

/* Annoyingly, we must fetch the low and high halves of each GPR
   separately. Use this type for each of those requests.  */
typedef uint32_t half_gregset_t[16];

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

/* Get info about the primary load module.
   z/OS TODO: Make this cache per-inferior.  */

CORE_ADDR
zos_get_load_addr (void)
{
  struct __ptrace_ldinfo *info;
  int ret;
  pid_t pid = inferior_ptid.pid ();
  size_t bufsz = sizeof (struct __ptrace_ldinfo) * 2;
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
      ret = ptrace_retry (PT_LDINFO, pid, info,
			  static_cast<int32_t>(bufsz), 0L);
      if (ret == 0 || bufsz == PTRACE_BUFF_SIZE_MAX)
	break;
      bufsz = std::min<size_t>(bufsz * 4, PTRACE_BUFF_SIZE_MAX);
      info = static_cast<struct __ptrace_ldinfo *>(xrealloc (info,
							     bufsz));
    }

  if (ret != 0)
    perror_with_name (_("Couldn't get get load info"));

  origin = info->text_origin;
  xfree (info);

  /* z/OS TODO: should include filename and PID.  */
  fprintf_unfiltered (gdb_stdlog,
		     _("Main module loaded at: 0x%016lx\n"), origin);
  gdb_flush (gdb_stdout);
  /* z/OS TODO: Is the initial load module always the first load module?  */

  return origin;
}

bool
zos_get_elf_info (CORE_ADDR *at_phdr, CORE_ADDR *at_phent,
		  CORE_ADDR *at_phnum)
{
  /* z/OS TODO: For now our elf header is always at our load address,
     but that's an implementation detail. Figure out a more robust
     way to find it.
     z/OS TODO: Getting the load addr all over again is wasteful.
     at this point we've aleady fetched it once. Cache it.  */
  gdb_byte ehdr[sizeof (Elf64_External_Ehdr)];
  size_t ent_off, num_off;
  CORE_ADDR phdr, phent, phnum;
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());

  phdr = zos_get_load_addr ();

  if (phdr == 0)
    return false;

  if (!target_read_memory (phdr, ehdr, sizeof (Elf64_External_Ehdr)))
    return false;

  /* Validate (just check magic bytes).   */
  if (ehdr[EI_MAG0] != ELFMAG0
      || ehdr[EI_MAG1] != ELFMAG1
      || ehdr[EI_MAG2] != ELFMAG2
      || ehdr[EI_MAG3] != ELFMAG3)
    return false;

  if (ehdr[EI_CLASS] != ELFCLASS32)
    {
      ent_off = offsetof (Elf64_External_Ehdr, e_phentsize);
      num_off = offsetof (Elf64_External_Ehdr, e_phnum);
    }
  else
    {
      ent_off = offsetof (Elf32_External_Ehdr, e_phentsize);
      num_off = offsetof (Elf32_External_Ehdr, e_phnum);
    }

  phent = extract_unsigned_integer (ehdr + ent_off, 2, byte_order);
  phnum = extract_unsigned_integer (ehdr + num_off, 2, byte_order);

  *at_phdr = phdr;
  *at_phent = phent;
  *at_phnum = phnum;

  return true;
}

/* Generate a fake auxv for the inferior.  */

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

/* Transfer data via ptrace into process PID's memory from WRITEBUF, or
   from process PID's memory into READBUF.  Start at target address ADDR
   and transfer up to LEN bytes.  Exactly one of READBUF and WRITEBUF
   must be non-null. Stores the number of transfered bytes into
   XFERED_LEN.  */

static enum target_xfer_status
zos_xfer_memory (gdb_byte *readbuf,
		 const gdb_byte *writebuf,
		 ULONGEST addr, ULONGEST len,
		 ULONGEST *xfered_len)
{
  pid_t pid = inferior_ptid.pid ();
  enum __ptrace_request req = readbuf ? PT_READ_BLOCK : PT_WRITE_BLOCK;
  gdb_byte *buf = readbuf ? readbuf : const_cast<gdb_byte *>(writebuf);
  ULONGEST n = 0;

  /* z/OS TODO: Check if we've captured any of the requested memory.  */

  /* The ptrace operations we use here have a max buffer size, so
     transfer in chunks.  */
  while (n < len)
    {
      size_t chunk = std::min<ULONGEST>(len - n, PTRACE_BUFF_SIZE_MAX);
      printf ("(%lx, %lu, %p)\n", addr + n, chunk, buf + n); fflush (NULL);

      errno = 0;
      ptrace_retry (req, pid, addr + n, chunk, buf + n);
      if (errno)
	{
	  if (debug_zos_nat)
	    perror_with_name ("ptrace memory transfer");
	  break;
	}
      n += chunk;
    }

  *xfered_len = n;

  if (n == len)
    return TARGET_XFER_OK;
  else
    {
      if (debug_zos_nat)
	fprintf_unfiltered (gdb_stdlog,
			    "z/OS memory transfer of length %lu failed"
			    "for addr %lx, transferred %lu bytes\n",
			    len, addr, n);
      /* z/OS TODO: Should we do a memory_error() here?  */
      return TARGET_XFER_E_IO;
    }
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
      /* The target is connected but no live inferior is selected.  Pass
	 this request down to a lower stratum (e.g., the executable
	 file).  */
      if (inferior_ptid == null_ptid)
	return TARGET_XFER_EOF;

      return zos_xfer_memory (readbuf, writebuf,
			      offset, len, xfered_len);

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
  ULONGEST pswa, pswm;
  gdb_byte buf[8];
  enum bfd_endian byte_order = gdbarch_byte_order (regcache->arch ());
  int regno;

  /* z/OS TODO: Eventually, we should use a PT_READ_GPR blockreq to
     fetch all this info at once.  */

  if (ptrace_retry (PT_REGSET, tid, &half_regs, 0L, 0L) < 0)
    perror_with_name (_("Couldn't get register low halves"));

  /* Regmaps don't work for setting the register values very well because
     we want to write directly to the low halves of registers, which
     regmaps don't easily support. Instead, we just do the direct
     write.  */
  for (regno = 0; regno <= 15; ++regno)
    regcache->raw_supply_part (regno + S390_R0_REGNUM, 4, 4,
			       (gdb_byte *) half_regs + 4 * regno);

  if (ptrace_retry (PT_REGHSET, tid, &half_regs, 0L, 0L) < 0)
    perror_with_name (_("Couldn't get register high halves"));

  for (regno = 0; regno <= 15; ++regno)
    regcache->raw_supply_part (regno + S390_R0_REGNUM, 0, 4,
			       (gdb_byte *) half_regs + 4 * regno);

  errno = 0;
  pswa = ptrace_retry (PT_READ_GPR, tid, PTRACE_REG_PSWA, 0L, 0L);
  if (errno != 0)
    perror_with_name ("Couldn't get pswa");

  store_unsigned_integer (buf, 8, byte_order, pswa & 0x7fffffff);
  regcache->raw_supply (S390_PSWA_REGNUM, buf);

  /* Only way to know if an error occurred for these is to check
     errno.  */
  errno = 0;
  pswm = ptrace_retry (PT_READ_GPR, tid, PTRACE_REG_PSWM, 0L, 0L);
  if (errno != 0)
    perror_with_name ("Couldn't get pswm");

  /* z/OS TODO: How are we supposed to massage the pswm?  */
  store_unsigned_integer (buf, 8, byte_order,
			  (pswm << 32) | (pswa & 0x80000000));
  regcache->raw_supply (S390_PSWM_REGNUM, buf);
}

static void
store_gpr (const struct regcache *regcache, int tid, int regno)
{
  uint32_t regpart;
  gdb_byte buf[8];
  int low = regno - S390_R0_REGNUM + PTRACE_REG_GPRL0;
  int high = regno - S390_R0_REGNUM + PTRACE_REG_GPRH0;

  regcache->raw_collect (regno, buf);
  regpart = (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]);
  if (ptrace_retry (PT_WRITE_GPR, tid, low, regpart, 0L) < 0)
    perror_with_name ("ptrace PT_WRITE_GPR");

  regpart = (buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7]);
  if (ptrace_retry (PT_WRITE_GPRH, tid, high, regpart, 0L) < 0)
    perror_with_name ("ptrace PT_WRITE_GPRH");
}

static void
store_high_gpr (const struct regcache *regcache, int tid, int regno)
{
  uint32_t regpart;
  gdb_byte buf[4];
  int high = regno - S390_R0_REGNUM + PTRACE_REG_GPRH0;

  regcache->raw_collect (regno, buf);
  regpart = (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]);
  if (ptrace_retry (PT_WRITE_GPRH, tid, high, regpart, 0L) < 0)
    perror_with_name ("ptrace PT_WRITE_GPR");
}

/* Store all valid general-purpose registers and the PSW in GDB's
   register cache into the process/thread specified by TID.  */

static void
store_regs (const struct regcache *regcache, int tid, int regnum)
{
  half_gregset_t half_regs;
  ULONGEST pswa, pswm;
  gdb_byte buf[8];
  int regno;
  uint32_t regpart;

  /* z/OS TODO: Eventually, we should use a PT_WRITE_GPR blockreq to
     store all this info at once.  */

  if (regnum == S390_PSWA_REGNUM || regnum == -1)
    {
      regcache->raw_collect (S390_PSWA_REGNUM, buf);
      regpart = (buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7]);
      if (ptrace_retry (PT_WRITE_GPR, tid, PTRACE_REG_PSWA, regpart, 0L) < 0)
	perror_with_name ("ptrace write PSWA");
    }

  /* The PSWM cannot be modified on z/OS, so we skip that step.  */

  if (S390_R0_REGNUM <= regnum && regnum <= S390_R15_REGNUM)
    store_gpr (regcache, tid, regnum);
  else if (S390_R0_UPPER_REGNUM <= regnum
	   && regnum <= S390_R15_UPPER_REGNUM)
    store_high_gpr (regcache, tid, regnum);
  else if (regnum == -1)
    for (regno = S390_R0_REGNUM; regno <= S390_R15_REGNUM; ++regno)
      store_gpr (regcache, tid, regno);
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
  pid_t tid = get_ptrace_pid (regcache->ptid ());

  /* z/OS TODO: Special case -1 into one big blockreq.  */

  if (regnum == -1 || gpr_regnum_p (regnum))
    store_regs (regcache, tid, regnum);

  /* z/OS TODO: All the rest.  */
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
