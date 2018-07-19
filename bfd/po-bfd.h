/* IBM z/OS Program Object support
   Copyright (C) 2018 Rocket Software
   Contributed by Michael Colavita (mcolavita@rocketsoftware.com)
 
   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef _PO_BFD_H
#define _PO_BFD_H

#include "po/common.h"
#include "po/internal.h"
#include "po/external.h"

#define po_tdata(bfd)  ((bfd) -> tdata.po_obj_data)
#define po_header(bfd) (po_tdata(bfd) -> header)
#define po_pmar(bfd) (po_tdata(bfd) -> pmar)
#define po_pmarl(bfd) (po_tdata(bfd) -> pmarl)
#define po_name(bfd) (po_tdata(bfd) -> name)

struct po_obj_tdata {
  struct po_internal_plmh  header;
  struct po_internal_pmar  pmar;
  struct po_internal_pmarl pmarl;
  char                     name[PO_NAME_SIZE];
};

#endif
