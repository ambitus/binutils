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

#ifndef _PO_INTERNAL_H
#define _PO_INTERNAL_H

struct po_internal_plmh;
struct po_internal_header_rec_decl;
struct po_internal_pmar;
struct po_external_pmarl;
struct po_internal_prat_range;

struct po_internal_plmh {
  char           fixed_eyecatcher[8];
  bfd_size_type  length;
  unsigned char  version;
  bfd_size_type  uncompressed_module_size;
  unsigned int   rec_decl_count;
};

struct po_internal_header_rec_decl {
  unsigned short rec_type;
  bfd_vma        rec_offset;
  bfd_vma        rec_length;
};

struct po_internal_po_name_header {
  unsigned int alias_count;
};

struct po_internal_po_name_header_entry {
  bfd_vma alias_offset;
  unsigned short alias_length;
  unsigned char flags;
  unsigned char alias_marker[2];
};

struct po_internal_pmar {
  unsigned short length;
  unsigned char  po_level;
  unsigned char  binder_level;
  unsigned char  attr1;
  unsigned char  attr2;
  unsigned char  attr3;
  unsigned char  attr4;
  unsigned char  attr5;
  unsigned char  apf_auth_code;
  bfd_size_type  virtual_storage_required;
  bfd_vma        main_entry_point_offset;
  bfd_vma        this_entry_point_offset;
  unsigned char  change_level_of_member;
  unsigned char  ssi_flag_byte;
  unsigned char  member_serial_number[2];
  unsigned char  extended_attributes[2];
};

struct po_internal_pmarl {
  unsigned short length;
  unsigned char  attr1;
  unsigned char  attr2;
  unsigned char  fill_char_value;
  unsigned char  po_sublevel;
  bfd_size_type  program_length_no_gas;
  bfd_size_type  length_text;
  bfd_vma        offset_text;
  bfd_size_type  length_binder_index;
  bfd_vma        offset_binder_index;
  bfd_size_type  prdt_length;
  bfd_vma        prdt_offset;
  bfd_size_type  prat_length;
  bfd_vma        prat_offset;
  unsigned int   po_virtual_pages;
  bfd_size_type  ls_loader_data_offset;
  /* TODO: PM2 deliniation? */
  unsigned short loadable_segment_count;
  unsigned short gas_table_entry_count;
  bfd_size_type virtual_storage_for_first_segment;
  bfd_size_type virtual_storage_for_second_segment;
  bfd_vma        offset_to_second_text_segment;
  unsigned char date_saved[4]; /* Julian packed decimal */
  unsigned char time_saved[4]; /* packed decimal hhmmss */
  char userid[8];
  /* TODO: PM3 deliniation? */
  unsigned char pm3_flags;
  unsigned char cms_flags;
  unsigned short deferred_class_count;
  bfd_size_type deferred_class_total_length;
  bfd_vma offset_to_first_deferred_class;
  bfd_vma offset_blit;
  /* TODO: PM4 deliniation? */
  unsigned char attr3;
  /* TODO: PM5 deliniation? */
};

struct po_internal_prat {
  unsigned char fixed_eyecatcher[8];
  bfd_size_type length;
  unsigned char version;
  unsigned int occupied_entries;
  unsigned int total_entries;
  unsigned short single_entry_length;
};

struct po_internal_prdt {
  unsigned char fixed_eyecatcher[8];
  bfd_size_type length;
  unsigned char version;
  bfd_size_type total_length;
};

struct po_internal_prdt_page_header {
  unsigned int page_number;
  unsigned short segment_index;
  unsigned char checksum[4];
  unsigned short count;
};

struct po_internal_prdt_page_reloc_header {
  unsigned char flags;
  unsigned char reference_id;
  unsigned short reloc_count;
};


enum po_reloc_type {
  R_390_PO_32,
  R_390_PO_64
};

struct po_internal_prdt_entry {
  enum po_reloc_type reloc_type; /* This is temporary before we enumerate */
  bfd_vma full_offset;
  unsigned long addend;
};

struct po_internal_lidx {
  unsigned char fixed_eyecatcher[8];
  bfd_size_type length;
  unsigned char version;
  unsigned int element_count;
};

struct po_internal_psegm {
  unsigned char fixed_eyecatcher[8];
  bfd_size_type length;
  unsigned char version;
  unsigned int entry_count;
};

struct po_internal_psegm_entry {
  bfd_size_type length;
  bfd_vma offset;
  unsigned char flags;
};

struct po_internal_lidx_entry {
  unsigned char type;
  bfd_vma entry_offset;
  bfd_size_type entry_length;
};

#endif

