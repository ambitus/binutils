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

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "genlink.h"
#include "po-bfd.h"
#include "elf/s390.h"

__attribute__((unused))
static
const unsigned char ibm1047_to_iso88591[256] = {
/*         0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F */
/* 0 */ 0x00, 0x01, 0x02, 0x03, 0x9C, 0x09, 0x86, 0x7F, 0x97, 0x8D, 0x8E, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
/* 1 */ 0x10, 0x11, 0x12, 0x13, 0x9D, 0x0A, 0x08, 0x87, 0x18, 0x19, 0x92, 0x8F, 0x1C, 0x1D, 0x1E, 0x1F,
/* 2 */ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x17, 0x1B, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x05, 0x06, 0x07,
/* 3 */ 0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9A, 0x9B, 0x14, 0x15, 0x9E, 0x1A,
/* 4 */ 0x20, 0xA0, 0xE2, 0xE4, 0xE0, 0xE1, 0xE3, 0xE5, 0xE7, 0xF1, 0xA2, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
/* 5 */ 0x26, 0xE9, 0xEA, 0xEB, 0xE8, 0xED, 0xEE, 0xEF, 0xEC, 0xDF, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5E,
/* 6 */ 0x2D, 0x2F, 0xC2, 0xC4, 0xC0, 0xC1, 0xC3, 0xC5, 0xC7, 0xD1, 0xA6, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
/* 7 */ 0xF8, 0xC9, 0xCA, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF, 0xCC, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
/* 8 */ 0xD8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xAB, 0xBB, 0xF0, 0xFD, 0xFE, 0xB1,
/* 9 */ 0xB0, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0xAA, 0xBA, 0xE6, 0xB8, 0xC6, 0xA4,
/* A */ 0xB5, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0xA1, 0xBF, 0xD0, 0x5B, 0xDE, 0xAE,
/* B */ 0xAC, 0xA3, 0xA5, 0xB7, 0xA9, 0xA7, 0xB6, 0xBC, 0xBD, 0xBE, 0xDD, 0xA8, 0xAF, 0x5D, 0xB4, 0xD7,
/* C */ 0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xAD, 0xF4, 0xF6, 0xF2, 0xF3, 0xF5,
/* D */ 0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0xB9, 0xFB, 0xFC, 0xF9, 0xFA, 0xFF,
/* E */ 0x5C, 0xF7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0xB2, 0xD4, 0xD6, 0xD2, 0xD3, 0xD5,
/* F */ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xB3, 0xDB, 0xDC, 0xD9, 0xDA, 0x9F};

__attribute__((unused))
static
const unsigned char iso88591_to_ibm1047[256] = {
/*         0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F */
/* 0 */ 0x00, 0x01, 0x02, 0x03, 0x37, 0x2D, 0x2E, 0x2F, 0x16, 0x05, 0x15, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
/* 1 */ 0x10, 0x11, 0x12, 0x13, 0x3C, 0x3D, 0x32, 0x26, 0x18, 0x19, 0x3F, 0x27, 0x1C, 0x1D, 0x1E, 0x1F,
/* 2 */ 0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D, 0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
/* 3 */ 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
/* 4 */ 0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
/* 5 */ 0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xAD, 0xE0, 0xBD, 0x5F, 0x6D,
/* 6 */ 0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
/* 7 */ 0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xC0, 0x4F, 0xD0, 0xA1, 0x07,
/* 8 */ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x06, 0x17, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x09, 0x0A, 0x1B,
/* 9 */ 0x30, 0x31, 0x1A, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3A, 0x3B, 0x04, 0x14, 0x3E, 0xFF,
/* A */ 0x41, 0xAA, 0x4A, 0xB1, 0x9F, 0xB2, 0x6A, 0xB5, 0xBB, 0xB4, 0x9A, 0x8A, 0xB0, 0xCA, 0xAF, 0xBC,
/* B */ 0x90, 0x8F, 0xEA, 0xFA, 0xBE, 0xA0, 0xB6, 0xB3, 0x9D, 0xDA, 0x9B, 0x8B, 0xB7, 0xB8, 0xB9, 0xAB,
/* C */ 0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9E, 0x68, 0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77,
/* D */ 0xAC, 0x69, 0xED, 0xEE, 0xEB, 0xEF, 0xEC, 0xBF, 0x80, 0xFD, 0xFE, 0xFB, 0xFC, 0xBA, 0xAE, 0x59,
/* E */ 0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9C, 0x48, 0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,
/* F */ 0x8C, 0x49, 0xCD, 0xCE, 0xCB, 0xCF, 0xCC, 0xE1, 0x70, 0xDD, 0xDE, 0xDB, 0xDC, 0x8D, 0x8E, 0xDF};

static const char eyecatcher_plmh[] = { 0xC9, 0xC5, 0xE6, 0xD7, 0xD3, 0xD4, 0xC8, 0x40 };
static const char eyecatcher_prat[] = { 0xC9, 0xC5, 0xE6, 0xD7, 0xD9, 0xC1, 0xE3, 0x40 };
static const char eyecatcher_prdt[] = { 0xC9, 0xC5, 0xE6, 0xD7, 0xD9, 0xC4, 0xE3, 0x40 };
static const char eyecatcher_lidx[] = { 0xC9, 0xC5, 0xE6, 0xD3, 0xC9, 0xC4, 0xE7, 0x40 };
static const char eyecatcher_psegm[] = { 0xC9, 0xC5, 0xE6, 0xD7, 0xE2, 0xC5, 0xC7, 0xD4 };
static const char text_pad[] = { 0xC9, 0xC5, 0xE6, 0xD7 };

static void
convert_iso88591_to_ibm1047 (char *ebcdic, char *ascii, bfd_size_type length)
{
  for (unsigned i = 0; i < length; i ++)
    ebcdic[i] = iso88591_to_ibm1047[(int) ascii[i]];
}

static void
bfd_po_swap_plmh_out (bfd *abfd, struct po_internal_plmh *src, struct po_external_plmh *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  dst->version = src->version;
  H_PUT_32 (abfd, src->length, &dst->length);
  H_PUT_32 (abfd, src->uncompressed_module_size, &dst->uncompressed_module_size);
  H_PUT_32 (abfd, src->rec_decl_count, &dst->rec_decl_count);
}

static void
bfd_po_swap_header_rec_decl_out (bfd *abfd, struct po_internal_header_rec_decl *src, struct po_external_header_rec_decl *dst)
{
  memset(dst, 0, sizeof(*dst));
  H_PUT_16 (abfd, src->rec_type, &dst->rec_type);
  H_PUT_32 (abfd, src->rec_offset, &dst->rec_offset);
  H_PUT_32 (abfd, src->rec_length, &dst->rec_length);
}

static void
bfd_po_swap_pmar_out (bfd *abfd, struct po_internal_pmar *src, struct po_external_pmar *dst)
{
  memset (dst, 0, sizeof(*dst));
  H_PUT_16 (abfd, src->length, &dst->length);
  dst->po_level = src->po_level;
  dst->binder_level = src->binder_level;
  dst->attr1 = src->attr1;
  dst->attr2 = src->attr2;
  dst->attr3 = src->attr3;
  dst->attr4 = src->attr4;
  dst->attr5 = src->attr5;
  dst->apf_auth_code = src->apf_auth_code;
  H_PUT_32 (abfd, src->virtual_storage_required, &dst->virtual_storage_required);
  H_PUT_32 (abfd, src->main_entry_point_offset, &dst->main_entry_point_offset);
  H_PUT_32 (abfd, src->this_entry_point_offset, &dst->this_entry_point_offset);
  dst->change_level_of_member = src->change_level_of_member;
  dst->ssi_flag_byte = src->ssi_flag_byte;
  memcpy(dst->member_serial_number, src->member_serial_number, sizeof(dst->member_serial_number));
  memcpy(dst->extended_attributes, src->extended_attributes, sizeof(dst->extended_attributes));
}

static void
bfd_po_swap_pmarl_out (bfd *abfd, struct po_internal_pmarl *src, struct po_external_pmarl *dst)
{
  char userid_ibm1047[8];

  memset (dst, 0, sizeof(*dst));
  H_PUT_16 (abfd, src->length, &dst->length);
  dst->attr1 = src->attr1;
  dst->attr2 = src->attr2;
  dst->fill_char_value = src->fill_char_value;
  dst->po_sublevel = src->po_sublevel;
  H_PUT_32 (abfd, src->program_length_no_gas, &dst->program_length_no_gas);
  H_PUT_32 (abfd, src->length_text, &dst->length_text);
  H_PUT_32 (abfd, src->offset_text, &dst->offset_text);
  H_PUT_32 (abfd, src->offset_binder_index, &dst->offset_binder_index);
  H_PUT_32 (abfd, src->prdt_length, &dst->prdt_length);
  H_PUT_32 (abfd, src->prdt_offset, &dst->prdt_offset);
  H_PUT_32 (abfd, src->prat_length, &dst->prat_length);
  H_PUT_32 (abfd, src->prat_offset, &dst->prat_offset);
  H_PUT_32 (abfd, src->po_virtual_pages, &dst->po_virtual_pages);
  H_PUT_32 (abfd, src->ls_loader_data_offset, &dst->ls_loader_data_offset);
  H_PUT_16 (abfd, src->loadable_segment_count, &dst->loadable_segment_count);
  H_PUT_16 (abfd, src->gas_table_entry_count, &dst->gas_table_entry_count);
  H_PUT_32 (abfd, src->virtual_storage_for_first_segment, &dst->virtual_storage_for_first_segment);
  H_PUT_32 (abfd, src->virtual_storage_for_second_segment, &dst->virtual_storage_for_second_segment);
  H_PUT_32 (abfd, src->offset_to_second_text_segment, &dst->offset_to_second_text_segment);
  memcpy (dst->date_saved, src->date_saved, sizeof(dst->date_saved));
  memcpy (dst->time_saved, src->time_saved, sizeof(dst->time_saved));
  convert_iso88591_to_ibm1047 (userid_ibm1047, src->userid, sizeof(userid_ibm1047));
  memcpy (dst->userid, userid_ibm1047, sizeof(dst->userid));
  dst->pm3_flags = src->pm3_flags;
  dst->cms_flags = src->cms_flags;
  H_PUT_16 (abfd, src->deferred_class_count, &dst->deferred_class_count);
  H_PUT_32 (abfd, src->deferred_class_total_length, &dst->deferred_class_total_length);
  H_PUT_32 (abfd, src->offset_to_first_deferred_class, &dst->offset_to_first_deferred_class);
  H_PUT_32 (abfd, src->offset_blit, &dst->offset_blit);
  dst->attr3 = src->attr3;
}

static void
bfd_po_swap_po_name_header_out (bfd *abfd, struct po_internal_po_name_header *src, struct po_external_po_name_header *dst)
{
  memset(dst, 0, sizeof(*dst));
  H_PUT_32 (abfd, src->alias_count, &dst->alias_count);
}

static void
bfd_po_swap_po_name_header_entry_out (bfd *abfd, struct po_internal_po_name_header_entry *src, struct po_external_po_name_header_entry *dst)
{
  memset(dst, 0, sizeof(*dst));
  H_PUT_32 (abfd, src->alias_offset, &dst->alias_offset);
  H_PUT_16 (abfd, src->alias_length, &dst->alias_length);
  dst->flags = src->flags;
  memcpy(dst->alias_marker, src->alias_marker, sizeof(dst->alias_marker));
}

static void
bfd_po_swap_prat_out (bfd *abfd, struct po_internal_prat *src, struct po_external_prat *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  H_PUT_32 (abfd, src->length, &dst->length);
  dst->version = src->version;
  H_PUT_32 (abfd, src->occupied_entries, &dst->occupied_entries);
  H_PUT_32 (abfd, src->total_entries, &dst->total_entries);
  H_PUT_16 (abfd, src->single_entry_length, &dst->single_entry_length);
}

static void
bfd_po_swap_prdt_out (bfd *abfd, struct po_internal_prdt *src, struct po_external_prdt *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  H_PUT_32 (abfd, src->length, &dst->length);
  dst->version = src->version;
  H_PUT_32 (abfd, src->total_length, &dst->total_length);
}

static void
bfd_po_swap_prdt_page_header_out (bfd *abfd, struct po_internal_prdt_page_header *src, struct po_external_prdt_page_header *dst)
{
  memset(dst, 0, sizeof(*dst));
  H_PUT_32 (abfd, src->page_number, &dst->page_number);
  H_PUT_16 (abfd, src->segment_index, &dst->segment_index);
  memcpy(dst->checksum, src->checksum, sizeof(dst->checksum));
  H_PUT_16 (abfd, src->count, &dst->reloc_count_total);
}

static void
bfd_po_swap_prdt_page_reloc_header_out (bfd *abfd, struct po_internal_prdt_page_reloc_header *src, struct po_external_prdt_page_reloc_header *dst)
{
  dst->flags = src->flags;
  dst->reference_id = src->reference_id;
  H_PUT_16 (abfd, src->reloc_count, &dst->reloc_count);
}

static void
bfd_po_swap_prdt_six_byte_reloc_out (bfd *abfd, const struct po_internal_prdt_entry *src, struct po_external_prdt_six_byte_reloc *dst)
{
  H_PUT_16 (abfd, src->full_offset, &dst->offset);
  H_PUT_32 (abfd, src->addend, &dst->value);
}

static void
bfd_po_swap_prdt_r_390_po_64_reloc_out (bfd *abfd, const struct po_internal_prdt_entry *src, struct po_external_prdt_r_390_po_64_reloc *dst)
{
  H_PUT_16 (abfd, src->full_offset, &dst->offset);
  H_PUT_64 (abfd, src->addend, &dst->value);
}

static void
bfd_po_swap_lidx_out (bfd *abfd, struct po_internal_lidx *src, struct po_external_lidx *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  H_PUT_32 (abfd, src->length, &dst->length);
  dst->version = src->version;
  H_PUT_32 (abfd, src->element_count, &dst->element_count);
}

static void
bfd_po_swap_lidx_entry_out (bfd *abfd, struct po_internal_lidx_entry *src, struct po_external_lidx_entry *dst)
{
  memset(dst, 0, sizeof(*dst));
  dst->type = src->type;
  H_PUT_32 (abfd, src->entry_length, &dst->entry_length);
  H_PUT_32 (abfd, src->entry_offset, &dst->entry_offset);
}

static void
bfd_po_swap_psegm_out (bfd *abfd, struct po_internal_psegm *src, struct po_external_psegm *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  H_PUT_32 (abfd, src->length, &dst->length);
  dst->version = src->version;
  H_PUT_32 (abfd, src->entry_count, &dst->entry_count);
}

static void
bfd_po_swap_psegm_entry_out (bfd *abfd, struct po_internal_psegm_entry *src, struct po_external_psegm_entry *dst)
{
  memset(dst, 0, sizeof(*dst));
  H_PUT_32 (abfd, src->length, &dst->length);
  H_PUT_32 (abfd, src->offset, &dst->offset);
  dst->flags = src->flags;
}

/*
 * This function finalizes the header of the program object, loading completed internal
 * representations into the po_obj_tdata structure. To do so, it traverses the structures
 * in order to compute their final lengths, uses these to compute the elements' offsets,
 * and substitutes these values in the appropriate locations.
 */
static bfd_boolean
bfd_po_finalize_header (bfd *abfd)
{
  if (po_headers_computed(abfd))
    return TRUE;

  unsigned int rec_num = 0;
  unsigned int file_pos = 0;

  /* Finalize header */
  const unsigned int rec_count = 8;
  po_header(abfd).length = PLMH_SIZE(rec_count);
  po_header(abfd).rec_decl_count = rec_count;

  po_rec_decl_count(abfd) = rec_count;
  po_rec_decls(abfd) = bfd_zmalloc2(rec_count, sizeof(struct po_internal_header_rec_decl));
  if (po_rec_decls(abfd) == NULL)
    return FALSE;

  /* Advance past header and record declarations */
  file_pos += PLMH_SIZE(rec_count);

  /* Create PO name/alias structures */
  const char po_name[] = "HELLO   ";
  const unsigned int aliases = 1;
  po_name_header(abfd).alias_count = aliases;
  po_name_header_entries(abfd) = bfd_zmalloc2(aliases, PO_NAME_HEADER_ENTRY_SIZE);
  if (po_name_header_entries(abfd) == NULL) /* TODO leaks */
    return FALSE;
  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_PO_NAME_HEADER,
    .rec_offset = file_pos,
    .rec_length = PO_NAME_HEADER_SIZE(aliases)
  };

  /* Advance past PO name header and entries */
  file_pos += PO_NAME_HEADER_SIZE(aliases);

  po_name_header_entries(abfd)[0] = (struct po_internal_po_name_header_entry) {
    .alias_offset = file_pos,
    .alias_length = strlen(po_name),
    .flags = 0,
    .alias_marker = { 0, 0 }
  };

  po_names(abfd) = bfd_zmalloc2(aliases, sizeof(char *));
  if (po_names(abfd) == NULL)
    return FALSE;
  po_names(abfd)[0] = bfd_zmalloc(strlen(po_name));
  if (po_names(abfd)[0] == NULL)
    return FALSE;
  memcpy(po_names(abfd)[0], po_name, strlen(po_name));

  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_PO_NAME,
    .rec_offset = file_pos,
    .rec_length = po_name_header_entries(abfd)[0].alias_length
  };

  /* Advance past PO name */
  file_pos += po_name_header_entries(abfd)[0].alias_length;


  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_PMAR,
    .rec_offset = file_pos,
    .rec_length = PMAR_SIZE + PMARL_SIZE
  };

  /* Advance past PMAR and PMARL */
  file_pos += PMAR_SIZE + PMARL_SIZE;

  /* Finalize PRAT */
  const unsigned int pages_needed = ROUND_UP(po_text_length(abfd), 0x1000) / 0x1000;
  po_prat_entries(abfd) = bfd_zmalloc2(sizeof(bfd_vma), pages_needed + 1);
  if (po_prat_entries(abfd) == NULL)
    return FALSE;

  po_prat(abfd).length = PRAT_SIZE(pages_needed + 1, 2); /* TODO rlds? */
  po_prat(abfd).occupied_entries = 0;
  po_prat(abfd).total_entries = pages_needed;
  po_prat(abfd).single_entry_length = 2;
  po_pmarl(abfd).prat_length = PRAT_BASE_SIZE;
  po_pmarl(abfd).prat_offset = po_prat(abfd).length;
  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_PRAT,
    .rec_offset = file_pos,
    .rec_length = po_prat(abfd).length
  };

  /* Advance past PRAT */
  unsigned int prat_size = PRAT_SIZE(pages_needed + 1, 2);
  po_prat_pad_bytes(abfd) = prat_size - (PRAT_BASE_SIZE + (pages_needed + 1) * 2);
  file_pos += prat_size;

  /* Finalize PRDT */
  const bfd_vma prdt_offset = file_pos;
  po_pmarl(abfd).prdt_offset = prdt_offset;
  unsigned int prdt_pos = PRDT_BASE_SIZE;
  for (unsigned i = 0; i < pages_needed; i ++)
  {
    const unsigned int entry_count = po_prdt_page_headers(abfd)[i].count;
    if (entry_count > 0) {
      /* TODO: this could cause out of bounds */
      memcpy(po_prdt_page_headers(abfd)[i].checksum, po_section_contents(abfd) + i * 0x1000, 4);
      po_prat_entries(abfd)[i] = prdt_pos;
      unsigned long full_entry_size = 0;
      bfd_boolean found32 = FALSE, found64 = FALSE;
      for (unsigned i2 = 0; i2 < entry_count; i2 ++)
      {
        const struct po_internal_prdt_entry *entry = &po_prdt_entries(abfd)[i][i2];
        switch (entry->reloc_type) {
          case R_390_PO_32:
            full_entry_size += 6;
            found32 = TRUE;
            break;
          case R_390_PO_64:
            full_entry_size += sizeof(struct po_external_prdt_r_390_po_64_reloc);
            found64 = TRUE;
            break;
        }
      }
      if (found32)
        full_entry_size += PRDT_RELOC_HEADER_SIZE;
      if (found64)
        full_entry_size += PRDT_RELOC_HEADER_SIZE;

      const unsigned int page_entry_size = ROUND_UP(full_entry_size, 4);
      po_prdt(abfd).total_length += page_entry_size;
      file_pos += PRDT_PAGE_HEADER_SIZE + page_entry_size;
      prdt_pos += PRDT_PAGE_HEADER_SIZE + page_entry_size;
      po_prat(abfd).occupied_entries ++;
    } else {
      po_prat_entries(abfd)[i] = 0;
    }
  }
  po_prdt(abfd).total_length += PRDT_SIZE_NO_ENTRY(po_prat(abfd).occupied_entries);
  po_pmarl(abfd).prdt_length = po_prdt(abfd).total_length;

  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_PRDT,
    .rec_offset = prdt_offset,
    .rec_length = po_prdt(abfd).total_length
  };

  /* Update PRAT pointers */
  po_prat_entries(abfd)[pages_needed] = po_prdt(abfd).total_length;

  /* Advance past PRDT */
  file_pos += PRDT_BASE_SIZE;

  /* Finalize LIDX */
  const unsigned int lidx_elements = 1;
  unsigned int lidx_element_num = 0;
  po_lidx_entries(abfd) = bfd_zmalloc2(lidx_elements, sizeof(struct po_internal_lidx_entry));
  if (po_lidx_entries(abfd) == NULL)
    return FALSE;

  po_lidx(abfd).element_count = lidx_elements;
  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_LIDX,
    .rec_offset = file_pos,
    .rec_length = LIDX_HEADER_BASE_SIZE
  };
  po_pmarl(abfd).ls_loader_data_offset = file_pos;

  /* Advance past LIDX and entries */
  file_pos += LIDX_HEADER_SIZE(lidx_elements);

  /* Finalize PSEGM */
  const unsigned int segments = 1;
  po_psegm_entries(abfd) = bfd_zmalloc2(segments, sizeof(struct po_internal_psegm_entry));
  if (po_psegm_entries(abfd) == NULL)
    return FALSE;

  po_psegm(abfd).length = PSEGM_SIZE(segments);
  po_psegm(abfd).entry_count =segments;

  po_lidx_entries(abfd)[lidx_element_num ++] = (struct po_internal_lidx_entry) {
    .type = LIDX_ENTRY_TYPE_PSEGM,
    .entry_offset = file_pos,
    .entry_length = PSEGM_SIZE(segments)
  };

  /* Advance past PSEGM */
  file_pos += PSEGM_SIZE(segments);

  BFD_ASSERT (lidx_element_num = lidx_elements);

  /* Advance past pad */
  const unsigned int remainder_words = (16 - (file_pos - (file_pos / 16 * 16))) / 4;
  for (unsigned i = 0; i < remainder_words; i ++)
    file_pos += sizeof(text_pad);
  po_text_pad_words(abfd) = remainder_words;

  /* Leave space for text TODO */
  po_text_offset(abfd) = file_pos;

  /* Finalize entry point */
  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_ENTRY,
    .rec_offset = file_pos,
    .rec_length = po_text_length(abfd)
  };

  file_pos += po_text_length(abfd);

  /* Empty BLXF reference */
  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_BXLF,
    .rec_offset = file_pos, /* TODO */
    .rec_length = 0
  };

  /* Finalize PMAR */
  const bfd_size_type module_size = ROUND_UP(file_pos, 0x1000);
  po_pmar(abfd).virtual_storage_required = po_text_length(abfd);
  po_pmar(abfd).main_entry_point_offset = bfd_get_start_address (abfd);
  po_pmar(abfd).this_entry_point_offset = bfd_get_start_address (abfd);

  /* Finalize PMARL TODO */
  po_pmarl(abfd).program_length_no_gas = module_size / 0x1000;
  po_pmarl(abfd).length_text = po_text_length(abfd);
  po_pmarl(abfd).offset_text = po_text_offset(abfd);
  po_pmarl(abfd).length_binder_index = 0; /* TODO */
  po_pmarl(abfd).offset_binder_index = file_pos; /* TODO */
  po_pmarl(abfd).po_virtual_pages = module_size / 0x1000;
  po_pmarl(abfd).loadable_segment_count = 1; /* TODO */
  po_pmarl(abfd).gas_table_entry_count = 0;
  po_pmarl(abfd).virtual_storage_for_first_segment = ROUND_UP(po_text_length(abfd), 0x1000);
  po_pmarl(abfd).virtual_storage_for_second_segment = 0;
  po_pmarl(abfd).offset_to_second_text_segment = 0;
  char date[] = { 0x20, 0x18, 0x10, 0x4F };
  char time[] = { 0x01, 0x83, 0x00, 0x5F };
  memcpy(po_pmarl(abfd).date_saved, date, sizeof(date));
  memcpy(po_pmarl(abfd).time_saved, time, sizeof(time));
  po_pmarl(abfd).deferred_class_count = 0;
  po_pmarl(abfd).offset_to_first_deferred_class = 0;
  po_pmarl(abfd).offset_blit = 0;

  /* Last header details */
  po_header(abfd).uncompressed_module_size = module_size;

  /* Complete PSEGM */
  po_psegm_entries(abfd)[0] = (struct po_internal_psegm_entry) {
    .length = po_text_length(abfd),
    .offset = po_text_offset(abfd),
    .flags = PSEGM_EXECUTABLE | PSEGM_UNKNOWN
  };

  BFD_ASSERT (rec_num == rec_count);

  po_headers_computed(abfd) = TRUE;

  return TRUE;
}

static bfd_boolean
bfd_po_output_psegm(bfd *abfd)
{
  char psegm[PSEGM_BASE_SIZE];
  bfd_po_swap_psegm_out(abfd, &po_psegm(abfd), (struct po_external_psegm *) psegm);
  if (bfd_bwrite(psegm, PSEGM_BASE_SIZE, abfd) != PSEGM_BASE_SIZE)
    return FALSE;

  char psegm_entry[PSEGM_ENTRY_SIZE];
  for (unsigned int i = 0; i < po_psegm(abfd).entry_count; i ++)
    {
      bfd_po_swap_psegm_entry_out(abfd, &po_psegm_entries(abfd)[i], (struct po_external_psegm_entry *) psegm_entry);
      if (bfd_bwrite(psegm_entry, PSEGM_ENTRY_SIZE, abfd) != PSEGM_ENTRY_SIZE)
        return FALSE;
    }

  return TRUE;
}

static bfd_boolean
bfd_po_output_header_lidx (bfd *abfd)
{
  /* Output LIDX header */
  char lidx[LIDX_HEADER_BASE_SIZE];
  bfd_po_swap_lidx_out(abfd, &po_lidx(abfd), (struct po_external_lidx *) lidx);
  if (bfd_bwrite(lidx, LIDX_HEADER_BASE_SIZE, abfd) != LIDX_HEADER_BASE_SIZE)
    return FALSE;
  
  /* Output LIDX header entries */
  char lidx_entry[LIDX_HEADER_ENTRY_SIZE];
  for (unsigned int i = 0; i < po_lidx(abfd).element_count; i ++)
    {
      bfd_po_swap_lidx_entry_out(abfd, &po_lidx_entries(abfd)[i], (struct po_external_lidx_entry *) lidx_entry);
      if (bfd_bwrite(lidx_entry, LIDX_HEADER_ENTRY_SIZE, abfd) != LIDX_HEADER_ENTRY_SIZE)
        return FALSE;
    }

  /* Output LIDX entries */
  for (unsigned int i = 0; i < po_lidx(abfd).element_count; i ++)
    {
      switch (po_lidx_entries(abfd)[i].type)
        {
          case LIDX_ENTRY_TYPE_PSEGM:
            if (!bfd_po_output_psegm(abfd))
              return FALSE;
            break;
          case LIDX_ENTRY_TYPE_PGSTB:
            return FALSE;
          case LIDX_ENTRY_TYPE_PDSIT:
            return FALSE;
          default:
            return FALSE;
        }
    }

  return TRUE;
}

static bfd_boolean
bfd_po_output_header (bfd *abfd)
{
  /* Output header */
  char header_buf[PLMH_BASE_SIZE];
  bfd_po_swap_plmh_out(abfd, &po_header(abfd), (struct po_external_plmh *) header_buf);
  if (bfd_seek(abfd, 0, SEEK_SET) != 0 || bfd_bwrite(header_buf, PLMH_BASE_SIZE, abfd) != PLMH_BASE_SIZE)
    goto fail_free;

  /* Output header record declarations */
  char rec_decl_buf[HEADER_REC_DECL_SIZE];
  for (unsigned int i = 0; i < po_rec_decl_count(abfd); i ++)
    {
      bfd_po_swap_header_rec_decl_out(abfd, &po_rec_decls(abfd)[i], (struct po_external_header_rec_decl *) rec_decl_buf);
      if (bfd_bwrite(rec_decl_buf, HEADER_REC_DECL_SIZE, abfd) != HEADER_REC_DECL_SIZE)
        goto fail_free;
    }

  /* Output PO name header */
  char name_header_buf[PO_NAME_HEADER_BASE_SIZE];
  bfd_po_swap_po_name_header_out(abfd, &po_name_header(abfd), (struct po_external_po_name_header *) name_header_buf);
  if (bfd_bwrite(name_header_buf, PO_NAME_HEADER_BASE_SIZE, abfd) != PO_NAME_HEADER_BASE_SIZE)
    goto fail_free;

  /* Output PO name header entries */
  char name_header_entry_buf[PO_NAME_HEADER_ENTRY_SIZE];
  for (unsigned int i = 0; i < po_name_header(abfd).alias_count; i ++)
    {
      bfd_po_swap_po_name_header_entry_out(abfd, &po_name_header_entries(abfd)[i], (struct po_external_po_name_header_entry *) name_header_entry_buf);
      if (bfd_bwrite(name_header_entry_buf, PO_NAME_HEADER_ENTRY_SIZE, abfd) != PO_NAME_HEADER_ENTRY_SIZE)
        goto fail_free;
    }


  /* Output PO names */
  for (unsigned int i = 0; i < po_name_header(abfd).alias_count; i ++)
    {
      const unsigned int alias_length = po_name_header_entries(abfd)[i].alias_length;
      char *name_ibm1047 = bfd_malloc(alias_length);
      if (name_ibm1047 == NULL)
        goto fail_free;
      convert_iso88591_to_ibm1047(name_ibm1047, po_names(abfd)[i], alias_length);
      if (bfd_bwrite(name_ibm1047, alias_length, abfd) != alias_length)
        goto fail_free;
      free(name_ibm1047);
    }

  /* Output PMAR */
  char pmar[PMAR_SIZE];
  bfd_po_swap_pmar_out(abfd, &po_pmar(abfd), (struct po_external_pmar *) pmar);
  if (bfd_bwrite(pmar, PMAR_SIZE, abfd) != PMAR_SIZE)
    goto fail_free;

  /* Output PMARL */
  char pmarl[PMARL_SIZE];
  bfd_po_swap_pmarl_out(abfd, &po_pmarl(abfd), (struct po_external_pmarl *) pmarl);
  if (bfd_bwrite(pmarl, PMARL_SIZE, abfd) != PMARL_SIZE)
    goto fail_free;

  /* Output PRAT and PRDT */
  char prat[PRAT_BASE_SIZE];
  bfd_po_swap_prat_out(abfd, &po_prat(abfd), (struct po_external_prat *) prat);
  if (bfd_bwrite(prat, PRAT_BASE_SIZE, abfd) != PRAT_BASE_SIZE)
    goto fail_free;

  char prat_entry[2];
  for (unsigned i = 0; i < po_prat(abfd).total_entries + 1; i ++) {
    unsigned short entry = po_prat_entries(abfd)[i];
    H_PUT_16 (abfd, entry, prat_entry);
    if (bfd_bwrite(prat_entry, 2, abfd) != 2)
      goto fail_free;
  }
  char prat_pad[8];
  memset(prat_pad, 0, sizeof(prat_pad));
  if (bfd_bwrite(prat_pad, po_prat_pad_bytes(abfd), abfd) != po_prat_pad_bytes(abfd))
    goto fail_free;

  char prdt[PRDT_BASE_SIZE];
  bfd_po_swap_prdt_out(abfd, &po_prdt(abfd), (struct po_external_prdt *) prdt);
  if (bfd_bwrite(prdt, PRDT_BASE_SIZE, abfd) != PRDT_BASE_SIZE)
    goto fail_free;

  char prdt_entry[8];
  char prdt_page_header[PRDT_PAGE_HEADER_SIZE];
  char prdt_reloc_header[PRDT_RELOC_HEADER_SIZE]; /* TODO: style */
  for (unsigned i = 0; i < po_prat(abfd).total_entries; i ++) {
    const unsigned int entry_count = po_prdt_page_headers(abfd)[i].count;
    if (entry_count > 0) {
      bfd_po_swap_prdt_page_header_out(abfd, &po_prdt_page_headers(abfd)[i], (struct po_external_prdt_page_header *) prdt_page_header);
      if (bfd_bwrite(prdt_page_header, PRDT_PAGE_HEADER_SIZE, abfd) != PRDT_PAGE_HEADER_SIZE)
        goto fail_free;

      /* Determine total size */
      unsigned long full_entry_size = 0;
      unsigned found32 = 0, found64 = 0;
      for (unsigned i2 = 0; i2 < entry_count; i2 ++)
      {
        const struct po_internal_prdt_entry *entry = &po_prdt_entries(abfd)[i][i2];
        switch (entry->reloc_type) {
          case R_390_PO_32:
            full_entry_size += 6;
            found32 ++;
            break;
          case R_390_PO_64:
            full_entry_size += sizeof(struct po_external_prdt_r_390_po_64_reloc);
            found64 ++;
            break;
        }
      }
      const unsigned int page_entry_size = ROUND_UP(full_entry_size, 4); /* TODO */
      if (found32) {
        struct po_internal_prdt_page_reloc_header page_header = (struct po_internal_prdt_page_reloc_header) {
          .flags = 0x01,
          .reference_id = 0,
          .reloc_count = found32
        };
        bfd_po_swap_prdt_page_reloc_header_out (abfd, &page_header, (struct po_external_prdt_page_reloc_header *) &prdt_reloc_header);
        if (bfd_bwrite(prdt_reloc_header, PRDT_RELOC_HEADER_SIZE, abfd) != PRDT_RELOC_HEADER_SIZE)
          goto fail_free;

        for (unsigned i2 = 0; i2 < entry_count; i2 ++)
        {
          struct po_internal_prdt_entry entry = po_prdt_entries(abfd)[i][i2];
          entry.full_offset &= 0x0fff;
          if (entry.reloc_type != R_390_PO_32)
            continue;
          bfd_po_swap_prdt_six_byte_reloc_out(abfd, &entry, (struct po_external_prdt_six_byte_reloc*) prdt_entry);
          if (bfd_bwrite (prdt_entry, 6, abfd) != 6)
            goto fail_free;
        }
      }

      if (found64) {
        struct po_internal_prdt_page_reloc_header page_header = (struct po_internal_prdt_page_reloc_header) {
          .flags = 0x81,
          .reference_id = 0,
          .reloc_count = found64
        };
        bfd_po_swap_prdt_page_reloc_header_out (abfd, &page_header, (struct po_external_prdt_page_reloc_header *) &prdt_reloc_header);
        if (bfd_bwrite(prdt_reloc_header, PRDT_RELOC_HEADER_SIZE, abfd) != PRDT_RELOC_HEADER_SIZE)
          goto fail_free;

        for (unsigned i2 = 0; i2 < entry_count; i2 ++)
        {
          struct po_internal_prdt_entry entry = po_prdt_entries(abfd)[i][i2];
          entry.full_offset &= 0x0fff;
          if (entry.reloc_type != R_390_PO_64)
            continue;
          bfd_po_swap_prdt_r_390_po_64_reloc_out(abfd, &entry, (struct po_external_prdt_r_390_po_64_reloc*) prdt_entry);
          if (bfd_bwrite (prdt_entry, sizeof(struct po_external_prdt_r_390_po_64_reloc), abfd) != sizeof(struct po_external_prdt_r_390_po_64_reloc))
            goto fail_free;
        }
      }

      const unsigned pad = page_entry_size - full_entry_size;
      char zero_pad[8];
      memset(zero_pad, 0, sizeof(zero_pad));
      if (bfd_bwrite(zero_pad, pad, abfd) != pad)
        goto fail_free;
    }
  }

  if (! bfd_po_output_header_lidx (abfd))
    goto fail_free;

  for (unsigned i = 0; i < po_text_pad_words(abfd); i ++)
    if (bfd_bwrite(text_pad, sizeof(text_pad), abfd) != sizeof(text_pad))
      goto fail_free;

  return TRUE;

fail_free:
  free(po_rec_decls(abfd));
  return FALSE;
}

static bfd_boolean
bfd_po_write_header (bfd *abfd)
{
  return bfd_po_finalize_header (abfd) && bfd_po_output_header (abfd);
}

static bfd_boolean
bfd_po_new_section_hook (bfd *abfd, sec_ptr sec)
{
  return _bfd_generic_new_section_hook (abfd, sec);
}

static bfd_boolean
bfd_po_set_section_contents (bfd *abfd ATTRIBUTE_UNUSED, sec_ptr sec,
			     const void *contents ATTRIBUTE_UNUSED,
			     file_ptr offset ATTRIBUTE_UNUSED,
			     bfd_size_type len ATTRIBUTE_UNUSED)
{
  if ((sec->flags & SEC_ALLOC) == 0)
    return TRUE;

  if (po_section_contents (abfd) == NULL)
    {
      struct bfd_section *s;
      bfd_vma full_size = 0;

      for (s = abfd->sections; s != NULL; s = s->next)
	if (s->vma + s->size > full_size)
	  full_size = s->vma + s->size;

      po_section_contents (abfd) = bfd_zmalloc (full_size);
      if (po_section_contents (abfd) == NULL)
	return FALSE;
    }

  memcpy (po_section_contents (abfd) + sec->vma + offset, contents, len);

  return TRUE;
}

static bfd_boolean
bfd_po_mkobject (bfd *abfd)
{
  /* Allocate and initialize the target-specific tdata.  */
  po_tdata (abfd) =
    (struct po_obj_tdata *) bfd_zalloc (abfd, sizeof (struct po_obj_tdata));

  if (po_tdata (abfd) == NULL)
    return FALSE;

  /* Initialize all parts of tdata to zeros.  */
  memset (po_tdata (abfd), 0, sizeof (struct po_obj_tdata));

  po_sizes_computed (abfd) = FALSE;
  po_headers_computed (abfd) = FALSE;

  /* Initialize internal header */
  memcpy(po_header(abfd).fixed_eyecatcher, eyecatcher_plmh, sizeof(eyecatcher_plmh));
  po_header(abfd).version = PLMH_VERSION;

  /* Initialize PMAR */
  po_pmar(abfd).length = PMAR_SIZE;
  po_pmar(abfd).po_level = PMAR_PO_LEVEL_PM4;
  po_pmar(abfd).binder_level = PMAR_BINDER_LEVEL_B5;

  /* Set default PMAR flags */
  po_pmar(abfd).attr1 |= PMAR_ATTR1_EXECUTABLE;
  po_pmar(abfd).attr2 |= PMAR_ATTR2_BINDER_F_LEVEL_REQ;
  po_pmar(abfd).attr2 |= PMAR_ATTR2_ORG0;
  // po_pmar(abfd).attr2 |= PMAR_ATTR2_NO_REPROCESS;
  po_pmar(abfd).attr3 |= PMAR_ATTR3_PMARL_PRESENT;
  po_pmar(abfd).attr4 |= PMAR_ATTR4_RMODE31;
  po_pmar(abfd).attr4 |= PMAR_AMODE64;

  /* Initialize PMARL */
  po_pmarl(abfd).length = PMARL_SIZE;

  /* Set default PMARL flags */
  po_pmarl(abfd).attr1 |= PMARL_ATTR1_NO_PDS_CONVERT;
  po_pmarl(abfd).attr2 |= PMARL_ATTR2_COMPRESSED;
  po_pmarl(abfd).attr2 |= PMARL_ATTR2_SEG1_RMODE31;
  memset(po_pmarl(abfd).userid, ' ', sizeof(po_pmarl(abfd).userid));

  /* Initialize PRAT and PRDT */
  memcpy(po_prat(abfd).fixed_eyecatcher, eyecatcher_prat, sizeof(eyecatcher_prat));
  po_prat(abfd).version = PRAT_VERSION;
  memcpy(po_prdt(abfd).fixed_eyecatcher, eyecatcher_prdt, sizeof(eyecatcher_prdt));
  po_prdt(abfd).version = PRDT_VERSION;
  po_prdt(abfd).length = PRDT_BASE_SIZE; 

  /* Initialize LIDX */
  memcpy(po_lidx(abfd).fixed_eyecatcher, eyecatcher_lidx, sizeof(eyecatcher_lidx));
  po_lidx(abfd).length = LIDX_HEADER_BASE_SIZE;
  po_lidx(abfd).version = LIDX_VERSION;

  /* Initialize PSEGM */
  memcpy(po_psegm(abfd).fixed_eyecatcher, eyecatcher_psegm, sizeof(eyecatcher_psegm));
  po_psegm(abfd).version = PSEGM_VERSION;

  return TRUE;
}

static bfd_boolean
bfd_po_write_object_contents (__attribute ((unused)) bfd *abfd)
{
  if (!bfd_po_write_header (abfd))
    return FALSE;

  /* Write text */
  if (po_section_contents(abfd) != NULL)
  {
    if (bfd_bwrite (po_section_contents(abfd), po_text_length(abfd), abfd) != po_text_length(abfd))
      return FALSE;
  }
  /* Pad length to nearest page */
  bfd_size_type full_len = po_text_offset(abfd) + po_text_length (abfd); /* TODO */
  if (bfd_seek (abfd, full_len, SEEK_SET) != 0)
    return FALSE;

  char zeros[0x1000];
  memset(zeros, 0, sizeof(zeros));
  bfd_size_type size_delta = ROUND_UP(full_len, 0x1000) - full_len;
  if (bfd_bwrite (zeros, size_delta, abfd) != size_delta)
    return FALSE;

  return TRUE;
}

static int
bfd_po_sizeof_headers (bfd *abfd ATTRIBUTE_UNUSED, struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  return 0;
}

static long
bfd_po_get_reloc_upper_bound (bfd *abfd ATTRIBUTE_UNUSED, sec_ptr sec)
{
  return (sec->reloc_count + 1) * sizeof (arelent *);
}

static long
bfd_po_canonicalize_reloc (bfd *abfd ATTRIBUTE_UNUSED, sec_ptr sec ATTRIBUTE_UNUSED, arelent **relocs ATTRIBUTE_UNUSED, struct bfd_symbol **syms ATTRIBUTE_UNUSED)
{
  return 0; /* TODO */
}

static reloc_howto_type *
bfd_po_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type reloc ATTRIBUTE_UNUSED)
{
  return 0;
}

static reloc_howto_type *
bfd_po_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *reloc ATTRIBUTE_UNUSED)
{
  return 0;
}

static bfd_boolean
bfd_po_initialize_prdt(bfd *abfd)
{
  unsigned page_count = ROUND_UP(po_text_length(abfd), 0x1000) / 0x1000;
  po_prdt_page_headers(abfd) = bfd_zmalloc2(page_count, sizeof(struct po_internal_prdt_page_header));
  if (po_prdt_page_headers(abfd) == NULL)
    return FALSE;
  for (unsigned i = 0; i < page_count; i ++)
  {
    po_prdt_page_headers(abfd)[i].page_number = i;
    po_prdt_page_headers(abfd)[i].segment_index = 1; /* TODO */
    po_prdt_page_headers(abfd)[i].count = 0;
  }

  po_prdt_entries(abfd) = bfd_zmalloc2(page_count, sizeof(struct po_internal_prdt_entry *));
  if (po_prdt_entries(abfd) == NULL)
    return FALSE;

  return TRUE;
}

static bfd_boolean
bfd_po_add_prdt_entry(bfd *abfd, struct po_internal_prdt_entry *entry)
{
  unsigned page_number = entry->full_offset / 0x1000;
  unsigned entry_count = po_prdt_page_headers(abfd)[page_number].count;
  if (entry_count == 0 || !(entry_count & (entry_count - 1)))
  {
    /* reallocation required */
    const unsigned new_size = entry_count ? entry_count * 2 : 1;
    po_prdt_entries(abfd)[page_number] = bfd_realloc2(po_prdt_entries(abfd)[page_number], new_size, sizeof(struct po_internal_prdt_entry));
    if (po_prdt_entries(abfd)[page_number] == NULL)
      return FALSE;
  }

  po_prdt_entries(abfd)[page_number][entry_count] = *entry;
  po_prdt_page_headers(abfd)[page_number].count ++;

  return TRUE;
}

/* Calculate the size of all sections.  */

static bfd_boolean
po_calculate_section_sizes (bfd *abfd, struct bfd_link_info *info)
{
  asection *s;
  struct bfd_link_order *p;
  arelent **reloc_vector = NULL;

  if (po_sizes_computed (abfd))
    return TRUE;

  /* Most sections are okay, however we may need to add data to some
     sections, and possibly create a few sections from scratch.  */

  /* z/OS TODO: We should only do this traversal in one place.  */
  for (s = abfd->sections; s != NULL; s = s->next)
    {
      /* If this section isn't getting loaded, skip it.
	 z/OS TODO: We shouldn't need to do this, take it out and see if it
	 works.  */
      if ((s->flags & SEC_ALLOC) == 0)
	continue;

      for (p = s->map_head.link_order; p != NULL; p = p->next)
	if (p->type == bfd_indirect_link_order)
	  {
	    long relsize, relcount;
	    arelent **parent;
	    asection *sec = p->u.indirect.section;

	    /* Don't check relocs for the following cases, either because
	       they indicate that we shouldn't be processing the section
	       or that the section has no relocs.  */
	    if ((sec->flags & SEC_RELOC) == 0
		|| (sec->flags & SEC_EXCLUDE) != 0
		|| sec->reloc_count == 0
		|| ((info->strip == strip_all || info->strip == strip_debugger)
		    && (sec->flags & SEC_DEBUGGING) != 0)
		|| bfd_is_abs_section (sec->output_section))
	      continue;

	    relsize = bfd_get_reloc_upper_bound (sec->owner, sec);
	    if (relsize < 0)
	      return FALSE;

	    reloc_vector = (arelent **) bfd_malloc (relsize);
	    if (reloc_vector == NULL)
	      return FALSE;

	    relcount =
	      bfd_canonicalize_reloc (sec->owner, sec, reloc_vector,
				      _bfd_generic_link_get_symbols (sec->owner));
	    if (relcount < 0)
	      goto error_return;

	    if (relcount == 0)
	      continue;

	    for (parent = reloc_vector; *parent != NULL; parent++)
	      {
		switch ((*parent)->howto->type)
		  {
		  case R_390_TLS_IEENT:
		    /* z/OS TODO: do a hash table lookup or something on
		       symbols here, register which ones we need GOT slots
		       for. Create such a slot. Later, when we are
		       resolving the relocs, look up the slot to use.  */
		    break;
		  default:
		    break;
		  }
	      }

	    free (reloc_vector);
	  }
    }

  /* z/OS TODO: for each symbol that we registered above, generate a
     GOT entry. We can even fill it in now.  */

  /* Compute text size TODO: right place?
     z/OS TODO: rename this, it's module size not text size.  */
  po_text_length(abfd) = 0;
  for (s = abfd->sections; s != NULL; s = s->next)
    if (s->vma + s->size > po_text_length (abfd))
      po_text_length(abfd) = s->vma + s->size;

  po_sizes_computed (abfd) = TRUE;
  return TRUE;

error_return:
  if (reloc_vector != NULL)
    free (reloc_vector);
  return FALSE;
}

static bfd_boolean
bfd_po_final_link (bfd *abfd, struct bfd_link_info *info)
{
  asection *s;
  arelent **reloc_vector = NULL;

  /* This target is executable-only, relocatable links with -r make no
     sense for us.  */
  if (bfd_link_relocatable (info))
    {
      bfd_set_error (bfd_error_invalid_operation);
      return FALSE;
    }

  BFD_ASSERT (!po_sizes_computed (abfd));
  BFD_ASSERT (!po_headers_computed (abfd));

  /* Perform standard link */
  if (!_bfd_generic_final_link(abfd, info))
    return FALSE;

  /* Calculate section sizes.  */
  if (!po_calculate_section_sizes (abfd, info))
    return FALSE;

  if (!bfd_po_initialize_prdt(abfd))
    return FALSE;

  /* Capture z/OS relocatable relocs */
  for (s = abfd->sections; s != NULL; s = s->next)
    {
      struct bfd_link_order *p;
      /* If this section isn't getting loaded, skip it.
	 z/OS TODO: We shouldn't need to do this, take it out and see if
	 it works.  */
      if ((s->flags & SEC_ALLOC) == 0)
	continue;

      for (p = s->map_head.link_order; p != NULL; p = p->next)
	{
	  if (p->type == bfd_indirect_link_order)
	    {
	      long reloc_size, reloc_count;
	      arelent **parent;
	      bfd *input_bfd = p->u.indirect.section->owner;
	      asection *input_section = p->u.indirect.section;

	      /* Don't check relocs for the following cases, either because
		 they indicate that we shouldn't be processing the section
		 or that the section has no relocs.  */
	      if ((input_section->flags & SEC_RELOC) == 0
		  || (input_section->flags & SEC_EXCLUDE) != 0
		  || input_section->reloc_count == 0
		  || ((info->strip == strip_all || info->strip == strip_debugger)
		      && (input_section->flags & SEC_DEBUGGING) != 0)
		  || bfd_is_abs_section (input_section->output_section))
		continue;

	      reloc_size = bfd_get_reloc_upper_bound (input_bfd, input_section);
	      if (reloc_size < 0)
		return FALSE;

	      if (reloc_size == 0)
		continue;

	      reloc_vector = (arelent **) bfd_malloc (reloc_size);
	      if (reloc_vector == NULL)
		return FALSE;

	      reloc_count =
		bfd_canonicalize_reloc (input_bfd, input_section, reloc_vector,
					_bfd_generic_link_get_symbols (input_bfd));

	      if (reloc_count < 0)
		goto error_return;

	      if (reloc_count == 0)
		{
		  free (reloc_vector);
		  continue;
		}

	      for (parent = reloc_vector; *parent != NULL; parent++)
		{
		  bfd_vma full_offset, addend;
		  char *dst_ptr;
		  asymbol *symbol = *(*parent)->sym_ptr_ptr;
		  if (symbol == NULL)
		    goto error_return;

		  /* z/OS TODO: It would be better if we could access
		     contents through output_section->contents.  */
		  dst_ptr = (po_section_contents (abfd)
			     + input_section->output_offset
			     + s->vma + (*parent)->address);

		  /* TODO: rewrite in terms of VMA when we check guarantees */
		  switch ((*parent)->howto->type)
		    {
		    case R_390_32:
		    case R_390_64:
		      {
			/* z/OS TODO: common symbols? */

			/* A symbol is unresolved if it belongs to the
			   undefined section.  */
			if ((symbol->flags & BSF_WEAK) != 0
			    && bfd_is_und_section (symbol->section))
			  {
			    /* Zero out unresolved weak symbol */
			    if ((*parent)->howto->type == R_390_64)
			      bfd_put_64 (info->output_bfd, 0, dst_ptr);
			    else
			      bfd_put_32 (info->output_bfd, 0, dst_ptr);
			    break;
			  }

			full_offset = (input_section->output_offset + s->vma
				       + (*parent)->address);

			/* TODO: condition value? */
			addend = (symbol->section->output_section->vma
				  + symbol->section->output_offset
				  + (*parent)->addend + symbol->value);

			struct po_internal_prdt_entry entry = {
			  .full_offset = full_offset,
			  .addend = addend,
			  .reloc_type = ((*parent)->howto->type == R_390_64
					 ? R_390_PO_64 : R_390_PO_32)
			};
			if (!bfd_po_add_prdt_entry (abfd, &entry))
			  goto error_return;
			break;
		      }
		    case R_390_TLS_IEENT:
		      /* z/OS TODO: We need to do some stuff here.  */
		      break;
		    case R_390_TLS_LE32:
		    case R_390_TLS_LE64:
		      {
			bfd_signed_vma tls_offset;
			asection *tls_section;

			/* Find the start of the combined TLS section.
			   z/OS TODO: This will need to be changed when we
			   remove the .tdatabss stuff from the linker script.
			   Look for .tdata and .tbss separately, process should
			   be similar for .tdata symbols, .tbss symbols should
			   add the size of .tdata to the output offset.  */
			tls_section = symbol->section->output_section;
			BFD_ASSERT (strcmp (tls_section->name, ".tdatabss") == 0);

			/* The symbol should resolve to the negated offset from
			   the start of the TLS template (combined .tdata and
			   .tbss sections) to the symbol.
			   Note: symbol->value seems to be the symbol's offset
			   into its input section.  */
			tls_offset = (symbol->section->output_offset
				      + symbol->value
				      - symbol->section->output_section->size);

			if (tls_section == NULL)
			  {
			    _bfd_error_handler
			      (_("TLS reloc without TLS section"));
			    bfd_set_error (bfd_error_wrong_format);
			    return FALSE;
			  }

			switch ((*parent)->howto->type)
			  {
			  case R_390_TLS_LE64:
			    bfd_put_64 (info->output_bfd,
					(bfd_vma) tls_offset, dst_ptr);
			    break;
			  case R_390_TLS_LE32:
			    /* z/OS TODO: check for overflow here.  */
			    bfd_put_32 (info->output_bfd,
					(bfd_vma) tls_offset, dst_ptr);
			    break;
			  default:
			    goto bad_reloc;
			  }

			break;
		      }
		    default:
		      if ((*parent)->howto->pc_relative)
			{
			  /* These are fine */
			  break;
			}
		    bad_reloc:
		      _bfd_error_handler
			(_("Unsupported reloc type %d"), (*parent)->howto->type);
		      bfd_set_error (bfd_error_wrong_format);
		    error_return:
		      if (reloc_vector)
			free (reloc_vector);
		      return FALSE;
		    }
		}
	      free (reloc_vector);
	    }
	  else if (p->type == bfd_data_link_order)
	    /* TODO: Is there anything else we need to do here?  */
	    continue;
	  else
	    /* TODO: handle bfd_undefined_link_order,
	       bfd_section_reloc_link_order, and bfd_symbol_reloc_link_order
	       if needed.  */
	    BFD_FAIL ();
	}
    }

  return TRUE;
}

/*
static bfd_boolean
bfd_po_indirect_link_order (bfd *output_bfd, struct bfd_link_info *info, asection *output_section, struct bfd_link_order *link_order, bfd_boolean generic_linker)
{
}*/


/* TODO disallow relocatable (incremental) */
const bfd_target s390_po_vec = {
  "po-s390",
  bfd_target_unknown_flavour,
  BFD_ENDIAN_BIG,
  BFD_ENDIAN_BIG,

  (HAS_RELOC | BFD_RELOC_8 | BFD_RELOC_16 | BFD_RELOC_24 | BFD_RELOC_32 | EXEC_P | HAS_SYMS | WP_TEXT),
  (SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_HAS_CONTENTS),
  0,
  ' ',
  8,
  4,

  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
    bfd_getb32, bfd_getb_signed_32, bfd_putb32,
    bfd_getb16, bfd_getb_signed_16, bfd_putb16,

  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
    bfd_getb32, bfd_getb_signed_32, bfd_putb32,
    bfd_getb16, bfd_getb_signed_16, bfd_putb16,

  { 
    _bfd_dummy_target,
    _bfd_dummy_target, /* TODO: bfd_po_object_p */
    _bfd_dummy_target,
    _bfd_dummy_target
  },

  {
    _bfd_bool_bfd_false_error,
    bfd_po_mkobject,
    _bfd_bool_bfd_false_error,
    _bfd_bool_bfd_false_error
  },

  {
    _bfd_bool_bfd_false_error,
    bfd_po_write_object_contents,
    _bfd_bool_bfd_false_error,
    _bfd_bool_bfd_false_error
  },

  /* Generic */
  _bfd_generic_close_and_cleanup,
  _bfd_generic_bfd_free_cached_info,
  bfd_po_new_section_hook,
  _bfd_generic_get_section_contents,
  _bfd_generic_get_section_contents_in_window,

  /* Copy */
  BFD_JUMP_TABLE_COPY(_bfd_generic), /* TODO? */
  
  /* Core */
  BFD_JUMP_TABLE_CORE(_bfd_nocore),

  /* Archive */
  BFD_JUMP_TABLE_ARCHIVE(_bfd_noarchive), /* TODO */

  /* Symbols */
  BFD_JUMP_TABLE_SYMBOLS(_bfd_nosymbols), /* TODO */

  /* Relocs */
  bfd_po_get_reloc_upper_bound,
  bfd_po_canonicalize_reloc, /* TODO: ??? */
  _bfd_generic_set_reloc,
  bfd_po_reloc_type_lookup,
  bfd_po_reloc_name_lookup,

  /* Write */
  _bfd_generic_set_arch_mach,
  bfd_po_set_section_contents,

  /* Link */
  bfd_po_sizeof_headers,
  bfd_generic_get_relocated_section_contents,
  bfd_generic_relax_section,
  _bfd_generic_link_hash_table_create,
  _bfd_generic_link_add_symbols,
  _bfd_generic_link_just_syms, /* TODO: ??? */
  _bfd_generic_copy_link_hash_symbol_type,
  //_bfd_generic_final_link,
  bfd_po_final_link,
  _bfd_generic_link_split_section,
  _bfd_generic_link_check_relocs, /* TODO */
  bfd_generic_gc_sections,
  bfd_generic_lookup_section_flags,
  bfd_generic_merge_sections,
  bfd_generic_is_group_section,
  bfd_generic_discard_group,
  _bfd_generic_section_already_linked,
  bfd_generic_define_common_symbol,
  _bfd_generic_link_hide_symbol,
  bfd_generic_define_start_stop,

  /* Dynamic */
  BFD_JUMP_TABLE_DYNAMIC(_bfd_nodynamic),

  NULL,

  NULL
};

