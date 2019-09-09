/* IBM z/OS Program Object support.
   Copyright (C) 2019 Free Software Foundation, Inc.
   Contributed by Michael Colavita <mcolavita@rocketsoftware.com>.

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

#define po_tdata(bfd)                     ((bfd) -> tdata.po_obj_data)

#define po_header(bfd)                    (po_tdata(bfd) -> header)
#define po_rec_decls(bfd)                 (po_tdata(bfd) -> rec_decls)
#define po_rec_decl_count(bfd)            (po_tdata(bfd) -> rec_decl_count)
#define po_pmar(bfd)                      (po_tdata(bfd) -> pmar)
#define po_pmarl(bfd)                     (po_tdata(bfd) -> pmarl)
#define po_name_header(bfd)               (po_tdata(bfd) -> po_name_header)
#define po_name_header_entries(bfd)       (po_tdata(bfd) -> po_name_header_entries)
#define po_names(bfd)                     (po_tdata(bfd) -> po_names)
#define po_prat(bfd)                      (po_tdata(bfd) -> prat)
#define po_prat_entries(bfd)              (po_tdata(bfd) -> prat_entries)
#define po_prdt(bfd)                      (po_tdata(bfd) -> prdt)
#define po_prdt_page_headers(bfd)         (po_tdata(bfd) -> prdt_page_headers)
#define po_prdt_entries(bfd)              (po_tdata(bfd) -> prdt_entries)
#define po_lidx(bfd)                      (po_tdata(bfd) -> lidx)
#define po_lidx_entries(bfd)              (po_tdata(bfd) -> lidx_entries)
#define po_psegm(bfd)                     (po_tdata(bfd) -> psegm)
#define po_psegm_entries(bfd)             (po_tdata(bfd) -> psegm_entries)
#define po_text_offset(bfd)             (po_tdata(bfd) -> text_offset)
#define po_text_length(bfd)             (po_tdata(bfd) -> text_length)
#define po_text_pad_words(bfd)             (po_tdata(bfd) -> text_pad_words)
#define po_prat_pad_bytes(bfd)             (po_tdata(bfd) -> prat_pad_bytes)
#define po_headers_computed(bfd)           (po_tdata(bfd) -> headers_computed)
#define po_section_contents(bfd)           (po_tdata(bfd) -> section_contents)
#define po_sizes_computed(bfd)		(po_tdata(bfd)->sizes_computed)
#define po_tbss(bfd)			(po_tdata (bfd)->tbss)

struct po_obj_tdata {
  /* High level internal structures */
  struct po_internal_plmh                   header;
  struct po_internal_pmar                   pmar;
  struct po_internal_pmarl                  pmarl;
  struct po_internal_prat                   prat;
  struct po_internal_prdt                   prdt;
  struct po_internal_lidx                   lidx;
  struct po_internal_psegm                  psegm;
  struct po_internal_po_name_header         po_name_header;

  /* Repeating internal structures TODO: refactor? */
  struct po_internal_header_rec_decl       *rec_decls;
  struct po_internal_relent               **prdt_entries;
  struct po_internal_prdt_page_header      *prdt_page_headers;
  struct po_internal_lidx_entry            *lidx_entries;
  struct po_internal_psegm_entry           *psegm_entries;
  struct po_internal_po_name_header_entry  *po_name_header_entries;
  char                                    **po_names;
  bfd_vma                                  *prat_entries;
  char                                     *section_contents;

  /* Computed values */
  unsigned                                  rec_decl_count;
  bfd_vma                                   text_offset;
  bfd_vma                                   text_length;
  unsigned int                              text_pad_words;
  unsigned int                              prat_pad_bytes;
  bfd_boolean                               headers_computed;
  bfd_boolean                               sizes_computed;

  /* TLS template information.  */
  asection				   *tbss;
};

#endif
