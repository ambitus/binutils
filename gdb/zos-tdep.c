/* Target-dependent code for z/OS.

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

/* z/OS TODO: All the abi stuff for this file.  */

/* Initialize OSABI for z/OS on 64-bit systems.  */

#include "defs.h"
#include "gdbarch.h"
#include "osabi.h"
#include "solib-svr4.h"
#include "s390-tdep.h"

#include "features/s390-linux32v1.c"
#include "features/s390-linux32v2.c"
#include "features/s390-linux64.c"
#include "features/s390-linux64v1.c"
#include "features/s390-linux64v2.c"
#include "features/s390-te-linux64.c"
#include "features/s390-vx-linux64.c"
#include "features/s390-tevx-linux64.c"
#include "features/s390-gs-linux64.c"
#include "features/s390x-linux64v1.c"
#include "features/s390x-linux64v2.c"
#include "features/s390x-te-linux64.c"
#include "features/s390x-vx-linux64.c"
#include "features/s390x-tevx-linux64.c"
#include "features/s390x-gs-linux64.c"

static void
s390_zos_init_abi_64 (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  const struct target_desc *tdesc = info.target_desc;
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  tdep->abi = ABI_LINUX_ZSERIES;

  // s390_linux_init_abi_any (info, gdbarch);

  set_solib_svr4_fetch_link_map_offsets (gdbarch,
					 svr4_lp64_fetch_link_map_offsets);
  // set_xml_syscall_file_name (gdbarch, XML_SYSCALL_FILENAME_S390X);
}

void
_initialize_zos_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_s390, bfd_mach_s390_64, GDB_OSABI_ZOS,
			  s390_zos_init_abi_64);

  /* Initialize the GNU/Linux target descriptions.  */
  initialize_tdesc_s390_linux32v1 ();
  initialize_tdesc_s390_linux32v2 ();
  initialize_tdesc_s390_linux64 ();
  initialize_tdesc_s390_linux64v1 ();
  initialize_tdesc_s390_linux64v2 ();
  initialize_tdesc_s390_te_linux64 ();
  initialize_tdesc_s390_vx_linux64 ();
  initialize_tdesc_s390_tevx_linux64 ();
  initialize_tdesc_s390_gs_linux64 ();
  initialize_tdesc_s390x_linux64v1 ();
  initialize_tdesc_s390x_linux64v2 ();
  initialize_tdesc_s390x_te_linux64 ();
  initialize_tdesc_s390x_vx_linux64 ();
  initialize_tdesc_s390x_tevx_linux64 ();
  initialize_tdesc_s390x_gs_linux64 ();
}
