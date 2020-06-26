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
#include "inf-child.h"
#include "inf-ptrace.h"

class zos_nat_target final : public inf_ptrace_target
{
public:
  /* Add our register access methods.  */
  void fetch_registers (struct regcache *, int) override;
  void store_registers (struct regcache *, int) override;

};

static zos_nat_target the_zos_nat_target;

/* Fetch register REGNUM from the child process.  If REGNUM is -1, do
   this for all registers.  */
void
zos_nat_target::fetch_registers (struct regcache *regcache, int regnum)
{
  /* TODO.  */
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
}
