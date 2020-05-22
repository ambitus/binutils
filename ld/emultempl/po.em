# This shell script emits a C file. -*- C -*-
#   Copyright (C) 2020 Free Software Foundation, Inc.
#   Contributed by ARM Ltd.
#
# This file is part of the GNU Binutils.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the license, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING3. If not,
# see <http://www.gnu.org/licenses/>.
#

# This file is sourced from elf32.em, and defines extra
# Program Object specific routines.

# Include the s390 elf extra bits.
source_em ${srcdir}/emultempl/s390.em

fragment <<EOF

static void
po_before_parse (void)
{
  /* Call the standard ELF routine.  */
  gld${EMULATION_NAME}_before_parse ();

  /* Prevent the generation of copy relocs. Since we never have a fixed
     load address, copy relocs would not avoid the need for other
     dynamic relocs.  */
  link_info.nocopyreloc = TRUE;
}

EOF

# We have our own before_parse function, but it calls
# the standard routine, so give it a different name.
LDEMUL_BEFORE_PARSE=po_before_parse
