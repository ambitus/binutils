/* IBM z/OS Program Object support
   Copyright (C) 2019 Free Software Foundation, Inc.
   Contributed by Michael Colavita <mcolavita@rocketsoftware.com>
   and Giancarlo Frix <gfrix@rocketsoftware.com>.

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
#include "elf-bfd.h"
#include "elf/s390.h"
#include "po-bfd.h"

/* Instead of using copy relocs, generate load-time relocations.
   Note that since we don't have a guaranteed load address, we would
   need load-time relocs in one form or another to even implement copy
   relocs. Note that, as always, this is only relevant for
   position-dependent shared libraries and executables.  */
#define ELIMINATE_COPY_RELOCS 1

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

static const char eyecatcher_plmh[] =
  { 0xC9, 0xC5, 0xE6, 0xD7, 0xD3, 0xD4, 0xC8, 0x40 };
static const char eyecatcher_prat[] =
  { 0xC9, 0xC5, 0xE6, 0xD7, 0xD9, 0xC1, 0xE3, 0x40 };
static const char eyecatcher_prdt[] =
  { 0xC9, 0xC5, 0xE6, 0xD7, 0xD9, 0xC4, 0xE3, 0x40 };
static const char eyecatcher_lidx[] =
  { 0xC9, 0xC5, 0xE6, 0xD3, 0xC9, 0xC4, 0xE7, 0x40 };
static const char eyecatcher_psegm[] =
  { 0xC9, 0xC5, 0xE6, 0xD7, 0xE2, 0xC5, 0xC7, 0xD4 };
static const char text_pad[] =
  { 0xC9, 0xC5, 0xE6, 0xD7 };
static const char no_checksum_val[] =
  { 0x95, 0x96, 0x83, 0x88 };  /* 'noch' in EBCDIC.  */

typedef bfd_vma prat_ent;

/* NOTE: Keep this structure in sync with
   the one declared in elf64-s390.c.  */
struct po_s390_obj_tdata
{
  struct elf_obj_tdata root;
  struct plt_entry *local_plt;
  char *local_got_tls_type;

  /* Program Object fields below here.  */
  /* High level internal structures */
  struct po_internal_plmh header;
  struct po_internal_pmar pmar;
  struct po_internal_pmarl pmarl;
  struct po_internal_prat prat;
  struct po_internal_prdt prdt;
  struct po_internal_lidx lidx;
  struct po_internal_psegm psegm;
  struct po_internal_po_name_header po_name_header;

  /* Repeating internal structures TODO: refactor? */
  struct po_internal_header_rec_decl *rec_decls;
  struct po_internal_prdt_page *prdt_pages;
  struct po_internal_lidx_entry *lidx_entries;
  struct po_internal_psegm_entry *psegm_entries;
  struct po_internal_po_name_header_entry *po_name_header_entries;
  char **po_names;
  prat_ent *prat_entries;
  char *section_contents;

  /* Computed values */
  unsigned rec_decl_count;
  unsigned int text_pad_words;
  bfd_boolean headers_computed;
  bfd_boolean sizes_computed;

  /* File offset of the start of the elf file. If this is zero then
     there is no contained elf file.  */
  ufile_ptr elf_offset;
};

#define po_tdata(bfd) ((struct po_s390_obj_tdata *) (bfd)->tdata.any)

#define po_header(bfd)			(po_tdata (bfd)->header)
#define po_rec_decls(bfd)		(po_tdata (bfd)->rec_decls)
#define po_rec_decl_count(bfd)		(po_tdata (bfd)->rec_decl_count)
#define po_pmar(bfd)			(po_tdata (bfd)->pmar)
#define po_pmarl(bfd)			(po_tdata (bfd)->pmarl)
#define po_name_header(bfd)		(po_tdata (bfd)->po_name_header)
#define po_name_header_entries(bfd)	(po_tdata (bfd)->po_name_header_entries)
#define po_names(bfd)			(po_tdata (bfd)->po_names)
#define po_prat(bfd)			(po_tdata (bfd)->prat)
#define po_prat_entries(bfd)		(po_tdata (bfd)->prat_entries)
#define po_prdt(bfd)			(po_tdata (bfd)->prdt)
#define po_prdt_pages(bfd)		(po_tdata (bfd)->prdt_pages)
#define po_lidx(bfd)			(po_tdata (bfd)->lidx)
#define po_lidx_entries(bfd)		(po_tdata (bfd)->lidx_entries)
#define po_psegm(bfd)			(po_tdata (bfd)->psegm)
#define po_psegm_entries(bfd)		(po_tdata (bfd)->psegm_entries)
#define po_text_pad_words(bfd)		(po_tdata (bfd)->text_pad_words)
#define po_headers_computed(bfd)	(po_tdata (bfd)->headers_computed)
#define po_section_contents(bfd)	(po_tdata (bfd)->section_contents)
#define po_sizes_computed(bfd)		(po_tdata (bfd)->sizes_computed)
#define po_elf_offset(bfd)		(po_tdata (bfd)->elf_offset)

#define write_ext(buf, abfd)					\
  (bfd_bwrite ((buf), sizeof (*buf), abfd) != sizeof (*buf))

static bfd_boolean
add_prdt_entry (bfd *abfd, int r_type, bfd_vma offset, bfd_vma addend);

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
bfd_po_swap_po_name_header_out (bfd *abfd,
				struct po_internal_po_name_header *src,
				struct po_external_po_name_header *dst)
{
  memset(dst, 0, sizeof(*dst));
  H_PUT_32 (abfd, src->alias_count, &dst->alias_count);
}

static void
bfd_po_swap_po_name_header_entry_out (bfd *abfd,
				      struct po_internal_po_name_header_entry *src,
				      struct po_external_po_name_header_entry *dst)
{
  memset(dst, 0, sizeof(*dst));
  H_PUT_32 (abfd, src->alias_offset, &dst->alias_offset);
  H_PUT_16 (abfd, src->alias_length, &dst->alias_length);
  dst->flags = src->flags;
  memcpy(dst->alias_marker, src->alias_marker, sizeof(dst->alias_marker));
}

static void
bfd_po_swap_prat_out (bfd *abfd,
		      struct po_internal_prat *src,
		      struct po_external_prat *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  H_PUT_32 (abfd, src->length, &dst->length);
  dst->version = src->version;
  H_PUT_32 (abfd, src->occupied_entries, &dst->occupied_entries);
  H_PUT_32 (abfd, src->total_entries, &dst->total_entries);
  H_PUT_16 (abfd, src->single_entry_length, &dst->single_entry_length);
  H_PUT_16 (abfd, src->unknown_flags, &dst->unknown_flags);
}

static void
bfd_po_swap_prdt_out (bfd *abfd,
		      struct po_internal_prdt *src,
		      struct po_external_prdt *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  H_PUT_32 (abfd, src->length, &dst->length);
  dst->version = src->version;
  H_PUT_32 (abfd, src->total_length, &dst->total_length);
}

static void
po_swap_prdt_page_header_out (bfd *abfd,
			      struct po_internal_prdt_page *src,
			      struct po_external_prdt_page_header *dst)
{
  H_PUT_32 (abfd, src->num, &dst->page_number);
  H_PUT_16 (abfd, src->seg_idx, &dst->segment_index);
  memcpy(dst->checksum, src->checksum, sizeof(dst->checksum));
  H_PUT_16 (abfd, src->count, &dst->reloc_count_total);
}

static void
po_swap_reloc_32_out (bfd *abfd,
		      const struct po_internal_relent *src,
		      struct po_external_reloc_32 *dst)
{
  /* We only keep the offset from the start of the page.  */
  unsigned short page_offset = src->offset & 0x0fff;
  H_PUT_16 (abfd, page_offset, &dst->offset);
  H_PUT_32 (abfd, src->addend, &dst->value);
}

static void
po_swap_reloc_32_ext_out (bfd *abfd,
			  const struct po_internal_relent *src,
			  struct po_external_reloc_32_ext *dst)
{
  unsigned short page_offset = src->offset & 0x0fff;
  dst->type = (unsigned char) src->type;
  dst->flags = src->flags;
  H_PUT_16 (abfd, page_offset, &dst->offset);
  H_PUT_32 (abfd, src->addend, &dst->value);
}

static void
po_swap_reloc_64_out (bfd *abfd,
		      const struct po_internal_relent *src,
		      struct po_external_reloc_64 *dst)
{
  unsigned short page_offset = src->offset & 0x0fff;
  H_PUT_16 (abfd, page_offset, &dst->offset);
  H_PUT_64 (abfd, src->addend, &dst->value);
}

static void
po_swap_reloc_64_ext_out (bfd *abfd,
			  const struct po_internal_relent *src,
			  struct po_external_reloc_64_ext *dst)
{
  unsigned short page_offset = src->offset & 0x0fff;
  dst->type = (unsigned char) src->type;
  dst->flags = src->flags;
  H_PUT_16 (abfd, page_offset, &dst->offset);
  H_PUT_64 (abfd, src->addend, &dst->value);
}

static void
bfd_po_swap_lidx_out (bfd *abfd, struct po_internal_lidx *src,
		      struct po_external_lidx *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  H_PUT_32 (abfd, src->length, &dst->length);
  dst->version = src->version;
  H_PUT_32 (abfd, src->element_count, &dst->element_count);
}

static void
bfd_po_swap_lidx_entry_out (bfd *abfd, struct po_internal_lidx_entry *src,
			    struct po_external_lidx_entry *dst)
{
  memset(dst, 0, sizeof(*dst));
  dst->type = src->type;
  H_PUT_32 (abfd, src->entry_length, &dst->entry_length);
  H_PUT_32 (abfd, src->entry_offset, &dst->entry_offset);
}

static void
bfd_po_swap_psegm_out (bfd *abfd, struct po_internal_psegm *src,
		       struct po_external_psegm *dst)
{
  memset(dst, 0, sizeof(*dst));
  memcpy(dst->fixed_eyecatcher, src->fixed_eyecatcher, sizeof(dst->fixed_eyecatcher));
  H_PUT_32 (abfd, src->length, &dst->length);
  dst->version = src->version;
  H_PUT_32 (abfd, src->entry_count, &dst->entry_count);
}

static void
bfd_po_swap_psegm_entry_out (bfd *abfd,
			     struct po_internal_psegm_entry *src,
			     struct po_external_psegm_entry *dst)
{
  memset(dst, 0, sizeof(*dst));
  H_PUT_32 (abfd, src->length, &dst->length);
  H_PUT_32 (abfd, src->offset, &dst->offset);
  dst->flags = src->flags;
}

static void
init_reloc_header (bfd *abfd,
		   enum po_reloc_type type, unsigned char ref_id,
		   unsigned short relcount,
		   struct po_external_prdt_reloc_header *header)
{
  header->type = (unsigned char) type;
  header->reference_id = ref_id;
  bfd_h_put_16 (abfd, relcount, &header->reloc_count);
}

static bfd_boolean
po_mkobject (bfd *abfd)
{
  /* Make idempodent for the multiple calls in elf_object_p.
     z/OS TODO: Make sure that this doesn't break anything like
     bfd_reinit() or related functionality.  */

  if (abfd->direction == read_direction
      && abfd->tdata.any != NULL)
    return TRUE;

  return bfd_elf_allocate_object (abfd, sizeof (struct po_s390_obj_tdata),
				  S390_ELF_DATA);
}

/* z/OS TODO: Make sure it's not possible for writes to happen before
   elf_backend_begin_write_processing.  */

static void
po_begin_write_processing (bfd *abfd,
			   struct bfd_link_info *link_info ATTRIBUTE_UNUSED)
{
  /* We output a full and proper elf executable contained in a
     program object wrapper. To do that, we hack the bfd output
     mechanisms so it appears we are outputting to an archive,
     leaving space for the program object header.  */
  if (bfd_link_executable (link_info)
      || bfd_link_dll (link_info))
    {
      po_elf_offset (abfd) = 0x1000 * 500;	/* TODO.  */

      BFD_ASSERT (abfd->my_archive == NULL);
      abfd->my_archive = abfd;
      /* abfd->origin = po_s390_tdata (abfd)->po_header_size;  */
      abfd->origin = po_elf_offset (abfd);
      /* NOTE: arelt_data is mostly invalid, it's only there to satisfy
	 a check inside _bfd_generic_get_section_contents.  */
      abfd->arelt_data = bfd_zmalloc (sizeof (struct areltdata));
      if (abfd->arelt_data == NULL)
	abort ();
      /* arelt_data->parsed_size must be set to bfd_get_size() before
	 certain other checks occur in the process of writing to file,
	 which are unrelated to the check mentioned above but
	 impossible to avoid while arelt_data is nonnull.
         However, right now bfd_get_size() is zero, so we set it
	 elsewhere.  */
    }
}

/* Special PO relocation processing.

   z/OS TODO: This is a bit inefficient, but to do better we would need
   our own howto table, which is possible.

   z/OS TODO: we need to forbid pc-relative weak relocs (because they are
   unimplementable for statically linked programs).  */

static bfd_reloc_status_type
po_final_link_relocate (reloc_howto_type *howto,
			bfd *input_bfd,
			asection *input_section,
			bfd_byte *contents,
			bfd_vma address,
			bfd_vma value,
			bfd_vma addend)
{
  bfd_vma full_offset;

  switch (howto->type)
    {
    case R_390_32:
    case R_390_64:
      full_offset = (input_section->output_section->vma
		     + input_section->output_offset
		     + address);
      if (input_section->flags & SEC_LOAD
	  && !(value == 0 && addend == 0))
	/* Have the OS do a runtime relocation.
	   z/OS TODO: This shouldn't be necessary for non-static
	   executables, we will be emitting corresponding ELF
	   relocs for the dynamic linker anyway.  */
	add_prdt_entry (input_section->output_section->symbol->the_bfd,
			(int) howto->type, full_offset, value + addend);
      break;

    default:
      break;
    }

  return _bfd_final_link_relocate (howto, input_bfd, input_section,
				   contents, address, value, addend);
}

/*
 * This function finalizes the header of the program object, loading completed internal
 * representations into the po_obj_tdata structure. To do so, it traverses the structures
 * in order to compute their final lengths, uses these to compute the elements' offsets,
 * and substitutes these values in the appropriate locations.
 */
static bfd_boolean
finalize_header (bfd *abfd)
{
  unsigned int rec_num = 0;
  unsigned int file_pos = 0;

  /* All pending writes need to be written before bfd_get_size actually
     reflects the size of the file.  */
  bfd_flush (abfd);

  const bfd_vma fsz = bfd_get_size (abfd);

  /* NOTE: We set arelt_data->parsed_size here as a hack to allow a
     check in bfd_bread() to suceed.  */
  ((struct areltdata *) (abfd->arelt_data))->parsed_size = fsz;

  /* z/OS TODO: We load the entire elf file right now. Needless to say,
     we need to fix that.  */
  const bfd_vma load_size = fsz - po_elf_offset (abfd);

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

  unsigned int pages_needed = ROUND_UP (load_size, 0x1000) / 0x1000;

  /* Finalize the PRAT and PRDT info.  */
  /* TODO rlds? */
  po_prat (abfd).total_entries = pages_needed =
    (pages_needed < po_prat (abfd).total_entries
     ? pages_needed : po_prat (abfd).total_entries);
  po_prat_entries (abfd) =
    bfd_realloc2 (po_prat_entries (abfd), pages_needed + 1, sizeof (prat_ent));

  po_prat (abfd).length = PRAT_SIZE (pages_needed + 1);
  po_prat (abfd).version = PRAT_VERSION;
  po_prat (abfd).single_entry_length = PRAT_ENTRY_SIZE;
  po_prat (abfd).unknown_flags = 0x00;
  /* occupied_entries is already set up.  */
  memcpy (po_prat (abfd).fixed_eyecatcher, eyecatcher_prat,
	  sizeof (eyecatcher_prat));

  po_prdt (abfd).version = PRDT_VERSION;
  po_prdt (abfd).length = PRDT_BASE_SIZE;
  memcpy (po_prdt (abfd).fixed_eyecatcher, eyecatcher_prdt,
	  sizeof (eyecatcher_prdt));

  po_pmarl (abfd).prat_length = PRAT_BASE_SIZE;
  po_pmarl (abfd).prat_offset = po_prat (abfd).length;

  po_rec_decls (abfd)[rec_num++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_PRAT,
    .rec_offset = file_pos,
    .rec_length = po_prat (abfd).length
  };

  /* Advance past PRAT */
  file_pos += po_prat (abfd).length;

  /* Calculate the size and position of the PRDT.
     There's a header for each page, then a generic header for PO_32
     and PO_64, in addition to the actual entries for both. PO_32_EXT
     and PO_64_EXT have no headers.  */
  const bfd_vma prdt_offset = file_pos;
  unsigned int prdt_pos = PRDT_BASE_SIZE;
  po_pmarl(abfd).prdt_offset = prdt_offset;
  file_pos += PRDT_BASE_SIZE;

  for (unsigned int page = 0; page < pages_needed; page++)
    {
      unsigned int entries = po_prdt_pages (abfd)[page].count;
      bfd_vma page_rel_size = PRDT_PAGE_HEADER_SIZE;
      bfd_boolean found32 = FALSE, found64 = FALSE;

      if (entries == 0)
	{
	  po_prat_entries (abfd)[page] = 0;
	  continue;
	}

      /* z/OS TODO: This will really get complicated once we start using
	 proper segments. Can we prevent checksum checking by setting
	 all checksums to noch?  */
      if (!po_prdt_pages (abfd)[page].no_checksum)
	{
	  char chsum[4];
	  if (bfd_seek (abfd, po_elf_offset (abfd) + 0x1000 * page,
			SEEK_SET) != 0
	      || bfd_bread (chsum, 4, abfd) != 4)
	    return FALSE;
	  memcpy (po_prdt_pages (abfd)[page].checksum, chsum, 4);
	}
      po_prat_entries (abfd)[page] = prdt_pos;

      for (unsigned int ent_num = 0; ent_num < entries; ent_num++)
	{
	  switch (po_prdt_pages (abfd)[page].relocs[ent_num].type)
	    {
	    case PO_32:
	      page_rel_size += 6;
	      found32 = TRUE;
	      break;
	    case PO_32_EXT:
	      page_rel_size += 8;
	      break;
	    case PO_64:
	      page_rel_size += 10;
	      found64 = TRUE;
	      break;
	    case PO_64_EXT:
	      page_rel_size += 12;
	      break;
	    }
	}
      if (found32)
        page_rel_size += PRDT_RELOC_HEADER_SIZE;
      if (found64)
        page_rel_size += PRDT_RELOC_HEADER_SIZE;

      BFD_ASSERT (page_rel_size <= MAX_PAGE_RELOCS_SIZE);

      page_rel_size = ROUND_UP (page_rel_size, 4);

      file_pos += page_rel_size;
      prdt_pos += page_rel_size;
      po_prdt (abfd).total_length += page_rel_size;
      po_prat (abfd).occupied_entries++;
    }
  po_pmarl (abfd).prdt_length = po_prdt(abfd).total_length;

  po_rec_decls (abfd)[rec_num].rec_type = PLMH_REC_TYPE_PRDT;
  po_rec_decls (abfd)[rec_num].rec_offset = prdt_offset;
  po_rec_decls (abfd)[rec_num].rec_length = po_prdt (abfd).total_length;
  rec_num++;

  /* Update PRAT pointers */
  po_prat_entries (abfd)[pages_needed] = po_prdt (abfd).total_length;

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

  BFD_ASSERT (lidx_element_num == lidx_elements);

  /* Advance past pad */
  const unsigned int remainder_words = (16 - (file_pos - (file_pos / 16 * 16))) / 4;
  for (unsigned int i = 0; i < remainder_words; i ++)
    file_pos += sizeof(text_pad);
  po_text_pad_words(abfd) = remainder_words;

  /* z/OS TODO: align here.  */
  /*
  file_pos = (file_pos + 0x1000 - 1) & ~(0x1000 - 1);
  */

  /* If this assert fails, then we have corrupted the elf file.  */
  BFD_ASSERT (file_pos <= po_elf_offset (abfd));

  /* Finalize entry point */
  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_ENTRY,
    .rec_offset = po_elf_offset (abfd),
    .rec_length = load_size
  };

  file_pos += load_size;

  /* Empty BLXF reference */
  po_rec_decls(abfd)[rec_num ++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_BXLF,
    .rec_offset = file_pos, /* TODO */
    .rec_length = 0
  };

  /* Finalize PMAR */
  const bfd_size_type module_size = ROUND_UP (fsz, 0x1000);
  po_pmar(abfd).virtual_storage_required = load_size;
  po_pmar(abfd).main_entry_point_offset = bfd_get_start_address (abfd);
  po_pmar(abfd).this_entry_point_offset = bfd_get_start_address (abfd);

  /* Finalize PMARL TODO */
  po_pmarl(abfd).program_length_no_gas = module_size / 0x1000;
  po_pmarl(abfd).length_text = load_size;
  po_pmarl (abfd).offset_text = po_elf_offset (abfd);
  po_pmarl(abfd).length_binder_index = 0; /* TODO */
  po_pmarl(abfd).offset_binder_index = file_pos; /* TODO */
  po_pmarl(abfd).po_virtual_pages = module_size / 0x1000;
  po_pmarl(abfd).loadable_segment_count = 1; /* TODO */
  po_pmarl(abfd).gas_table_entry_count = 0;
  po_pmarl (abfd).virtual_storage_for_first_segment =
    ROUND_UP (load_size, 0x1000);
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
    .length = load_size,
    .offset = po_elf_offset (abfd),
    .flags = PSEGM_EXECUTABLE | PSEGM_UNKNOWN
  };

  BFD_ASSERT (rec_num == rec_count);

  char zeros[0x1000];
  memset(zeros, 0, sizeof (zeros));
  bfd_size_type size_delta = ROUND_UP (fsz, 0x1000) - fsz;
  if (bfd_seek (abfd, fsz, SEEK_SET) != 0
      || bfd_bwrite (zeros, size_delta, abfd) != size_delta)
    return FALSE;

  po_headers_computed(abfd) = TRUE;

  return TRUE;
}

static ATTRIBUTE_UNUSED bfd_boolean
po_prep_headers (bfd *abfd)
{
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

  /* PRAT and PRDT are initialized elsewhere.  */

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

  char prat_entry[4];
  for (unsigned int i = 0; i < po_prat(abfd).total_entries + 1; i++) {
    unsigned int entry = po_prat_entries(abfd)[i];
    H_PUT_32 (abfd, entry, prat_entry);
    if (bfd_bwrite(prat_entry, 4, abfd) != 4)
      goto fail_free;
  }

  char prdt[PRDT_BASE_SIZE];
  bfd_po_swap_prdt_out(abfd, &po_prdt(abfd), (struct po_external_prdt *) prdt);
  if (bfd_bwrite(prdt, PRDT_BASE_SIZE, abfd) != PRDT_BASE_SIZE)
    goto fail_free;

  /* Output the PRDT.  */
  char zero_pad[4];
  zero_pad[0] = zero_pad[1] = zero_pad[2] = zero_pad[3] = 0;
  for (unsigned int page = 0; page < po_prat(abfd).total_entries; page++)
    {
      union {
	struct po_external_reloc_32 r32;
	struct po_external_reloc_32_ext r32ext;
	struct po_external_reloc_64 r64;
	struct po_external_reloc_64_ext r64ext;
      } prdt_entry;
      struct po_external_prdt_page_header page_header;
      struct po_external_prdt_reloc_header reloc_header;
      bfd_size_type ent_num, pad;
      bfd_size_type page_rel_size = 0, page_full_size;
      bfd_size_type found32 = 0, found64 = 0;
      unsigned int entry_count = po_prdt_pages (abfd)[page].count;

      if (entry_count == 0)
	continue;

      po_swap_prdt_page_header_out (abfd,
				    &po_prdt_pages (abfd)[page],
				    &page_header);
      if (write_ext (&page_header, abfd))
        goto fail_free;

      /* Determine total size */
      for (ent_num = 0; ent_num < entry_count; ent_num++)
	{
	  switch (po_prdt_pages (abfd)[page].relocs[ent_num].type)
	    {
	    case PO_32:
	      page_rel_size += 6;
	      found32++;
	      break;
	    case PO_32_EXT:
	      page_rel_size += 8;
	      break;
	    case PO_64:
	      page_rel_size += 10;
	      found64++;
	      break;
	    case PO_64_EXT:
	      page_rel_size += 12;
	      break;
	    }
	}

      BFD_ASSERT (page_rel_size % 2 == 0);
      BFD_ASSERT (page_rel_size <= MAX_PAGE_RELOCS_SIZE);
      BFD_ASSERT (found32 <= 4096 / 4);
      BFD_ASSERT (found64 <= 4096 / 8);

      page_full_size = ROUND_UP (page_rel_size, 4);
      pad = page_full_size - page_rel_size;

      if (found32)
	{
	  /* Output regular 32-bit relocs.  */
	  init_reloc_header (abfd, PO_32, 0,
			     (unsigned short) found32, &reloc_header);
	  if (write_ext (&reloc_header, abfd))
	    goto fail_free;

	  for (ent_num = 0; ent_num < entry_count; ent_num++)
	    {
	      struct po_internal_relent *r_ent =
		&po_prdt_pages (abfd)[page].relocs[ent_num];

	      if (r_ent->type != PO_32)
		continue;

	      po_swap_reloc_32_out (abfd, r_ent, &prdt_entry.r32);

	      if (write_ext (&prdt_entry.r32, abfd))
		goto fail_free;
	    }
	}
      if (found64)
	{
	  /* Output regular 64-bit relocs.  */
	  init_reloc_header (abfd, PO_64, 0,
			     (unsigned short) found64, &reloc_header);
	  if (write_ext (&reloc_header, abfd))
	    goto fail_free;

	  for (ent_num = 0; ent_num < entry_count; ent_num++)
	    {
	      struct po_internal_relent *r_ent =
		&po_prdt_pages (abfd)[page].relocs[ent_num];

	      if (r_ent->type != PO_64)
		continue;

	      po_swap_reloc_64_out (abfd, r_ent, &prdt_entry.r64);

	      if (write_ext (&prdt_entry.r64, abfd))
		goto fail_free;
	    }
	}
      if (found32 + found64 < entry_count)
	{
	  /* Output the headerless relocs.  */
	  for (ent_num = 0; ent_num < entry_count; ent_num++)
	    {
	      struct po_internal_relent *r_ent =
		&po_prdt_pages (abfd)[page].relocs[ent_num];

	      switch (r_ent->type)
		{
		case PO_32:
		case PO_64:
		  continue;

		case PO_32_EXT:
		  po_swap_reloc_32_ext_out (abfd, r_ent,
					    &prdt_entry.r32ext);
		  if (write_ext (&prdt_entry.r32ext, abfd))
		    goto fail_free;
		  break;

		case PO_64_EXT:
		  po_swap_reloc_64_ext_out (abfd, r_ent,
					    &prdt_entry.r64ext);
		  if (write_ext (&prdt_entry.r64ext, abfd))
		    goto fail_free;
		  break;

		default:
		  bfd_set_error (bfd_error_bad_value);
		  goto fail_free;
		}
	    }
	}

      /* Pad each page entry in the PRDT to a fullword.  */
      if (bfd_bwrite (&zero_pad, pad, abfd) != pad)
        goto fail_free;
    }

  if (! bfd_po_output_header_lidx (abfd))
    goto fail_free;

  for (unsigned int i = 0; i < po_text_pad_words(abfd); i ++)
    if (bfd_bwrite(text_pad, sizeof(text_pad), abfd) != sizeof(text_pad))
      goto fail_free;

  /*
  file_ptr pad;
  file_ptr file_pos = bfd_tell (abfd);
  if (file_pos == -1)
    return FALSE;

  pad = 0x1000 - (file_pos & 0xFFF);
  BFD_ASSERT (pad >= 0);

  char *zeros[0x1000] = {0};
  if (pad > 0 && bfd_bwrite (zeros, (bfd_size_type)pad, abfd) != (bfd_size_type)pad)
    return FALSE;
  */

  return TRUE;

fail_free:
  free(po_rec_decls(abfd));
  return FALSE;
}

/* Add an entry to the PRDT, which will cause the loader to resolve
   the given absolute relocation at load-time. The relocation, described
   by RELENT, is located at OFFSET from the start of the module.  */

static bfd_boolean
add_prdt_entry (bfd *abfd, int r_type, bfd_vma offset, bfd_vma addend)
{
  unsigned int curr;
  struct po_internal_relent *entry;
  bfd_size_type page = offset / 0x1000;
  bfd_boolean no_cksum = FALSE;

  if (page > 4294967295)
    {
      _bfd_error_handler
	/* xgettext:c-format */
	(_("Page number for reloc is unrepresentable (%lu)"), page);
      bfd_set_error (bfd_error_file_too_big);
      return FALSE;
    }

  unsigned int pgs = po_prat (abfd).total_entries;

  /* Grow the page entry array if needed.
     We always need at least one extra entry for cross-page relocs.  */
  if (pgs < page + 2)
    {
      unsigned int new_pgs = (page + 5) * 3 / 2;

      po_prdt_pages (abfd) =
	bfd_realloc2 (po_prdt_pages (abfd), new_pgs,
		      sizeof (struct po_internal_prdt_page));
      po_prat_entries (abfd) =
	bfd_realloc2 (po_prat_entries (abfd), new_pgs + 1,
		      sizeof (prat_ent));
      if (po_prdt_pages (abfd) == NULL)
	return FALSE;

      for (unsigned int pg = pgs; pg < new_pgs; ++pg)
	{
	  struct po_internal_prdt_page *p = &po_prdt_pages (abfd)[pg];
	  p->num = pg;
	  p->seg_idx = 1;
	  p->checksum[0] = p->checksum[1] =
	    p->checksum[2] =  p->checksum[3] = 0;
	  p->count = 0;
	  p->no_checksum = FALSE;
	  p->relocs = NULL;
	  po_prat_entries (abfd)[pg] = 0;
	}
      po_prat_entries (abfd)[new_pgs] = 0;
      po_prat (abfd).total_entries = new_pgs;
    }

  curr = po_prdt_pages (abfd)[page].count++;

  /* Grow the reloc entry array if needed. We keep the reloc arrays a
     power of two.  */
  if (curr == 0 || !(curr & (curr - 1)))
    {
      /* reallocation required */
      unsigned int new_size = curr ? curr * 2 : 4;
      po_prdt_pages (abfd)[page].relocs =
	bfd_realloc2 (po_prdt_pages (abfd)[page].relocs,
		      new_size, sizeof (struct po_internal_relent));
      if (po_prdt_pages (abfd)[page].relocs == NULL)
	return FALSE;
    }

  entry = &po_prdt_pages (abfd)[page].relocs[curr];
  entry->offset = offset;

  /* If a reloc intersects with the checksum area,
     the checksum needs to be set to a special value.  */
  if ((offset & 0xFFF) < 4)
    {
      po_prdt_pages (abfd)[page].no_checksum = TRUE;
      memcpy (po_prdt_pages (abfd)[page].checksum, no_checksum_val, 4);
    }

  /* Figure out which type of reloc we should use.  */
  switch (r_type)
    {
    case R_390_32:
      if (addend > 4294967295)
	{
	  _bfd_error_handler
	    /* xgettext:c-format */
	    (_("Addend for 32-bit abs reloc is too large (%lu)"), addend);
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      if (offset % 4 == 0)
	{
	  entry->type = PO_32;
	  entry->flags = 0;  /* unused.  */
	}
      else
	{
	  entry->type = PO_32_EXT;
	  entry->flags = PO_32_RELOC_UNALIGNED;

	  if (offset % 0x1000 > 0xffc)
	    no_cksum = TRUE;
	}
      break;

    case R_390_64:
      if (offset % 8 == 0)
	{
	  entry->type = PO_64;
	  entry->flags = 0;  /* unused.  */
	}
      else
	{
	  entry->type = PO_64_EXT;

	  if (offset % 0x1000 <= 0xff8)
	    entry->flags = PO_64_RELOC_UNALIGNED;
	  else
	    {
	      entry->flags = PO_64_RELOC_XPAGE;
	      no_cksum = TRUE;
	    }
	}
      break;

    default:
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  if (no_cksum)
    {
      /* This reloc will cross the page, so the next page can't
	 have a checksum.  */
      po_prdt_pages (abfd)[page + 1].no_checksum = TRUE;
      memcpy (po_prdt_pages (abfd)[page + 1].checksum,
	      no_checksum_val, 4);
    }

  entry->addend = addend;

  return TRUE;
}

static bfd_boolean
po_final_link (bfd *abfd, struct bfd_link_info *info)
{
  /* This target is executable-only, relocatable links with -r make no
     sense for us.  */
  if (bfd_link_relocatable (info))
    {
      bfd_set_error (bfd_error_invalid_operation);
      return FALSE;
    }

  /* Initialize the structures used to record load-time relocations. We
     only initialize the parts of the structure that will be used during
     the link. The rest of the fields are filled in by po_record_headers.

     This format uses two interrelated structures, which we refer to by
     their eyecatchers, PRAT and PRDT.  */

  po_prat (abfd).occupied_entries = 0;

  /* This is the number of allocated elements in po_prdt_pages.  */
  po_prat (abfd).total_entries = 0;

  /* FIXME: These grow, and we never free them.  */
  po_prdt_pages (abfd) = NULL;
  po_prat_entries (abfd) = NULL;

  /* Invoke the regular ELF backend linker.  */
  if (!bfd_elf_final_link (abfd, info))
    return FALSE;

  return TRUE;
}

static bfd_boolean
po_write_object_contents (bfd *abfd)
{
  if (!_bfd_elf_write_object_contents (abfd))
    return FALSE;

  /* z/OS TODO: We actually want to check bfd_link_executable here, but
     we can't since we don't have a link_info. he current approach might
     have unintended consequences.  */
  if (abfd->my_archive != NULL)
    {
      /* po_begin_write_processing should have already been called.
	 Undo the archive hack.  */

      abfd->my_archive = NULL;
      /* arelt_data gets freed by bfd_close.  */

      /* Make the Elf type ET_DYN, which helps a few programs. We do this
         after the Elf file is finished being written out to avoid
	 confusing the Elf backend.  */
      Elf64_External_Ehdr *ehdr;
      bfd_byte e_type[sizeof (ehdr->e_type)];
      bfd_put_16 (abfd, ET_DYN, &e_type[0]);
      if (bfd_seek (abfd, po_elf_offset (abfd) + EI_NIDENT, SEEK_SET) != 0
	  || bfd_bwrite (&e_type[0],
			 sizeof (ehdr->e_type), abfd) != sizeof (ehdr->e_type))
	return FALSE;

      /* z/OS TODO: merge prep_headers, finalize_header, and output_header.  */
      if (!po_prep_headers (abfd))
	return FALSE;
      if (!finalize_header (abfd))
	return FALSE;
      if (!bfd_po_output_header (abfd))
	return FALSE;

      for (unsigned int page = 0; page < po_prat (abfd).total_entries; ++page)
	free (po_prdt_pages (abfd)[page].relocs);
      if (po_prdt_pages (abfd))
	free (po_prdt_pages (abfd));
      if (po_prat_entries (abfd))
	free (po_prat_entries (abfd));
      free (po_rec_decls (abfd));
      free (po_name_header_entries (abfd));
      free (po_names (abfd)[0]);
      free (po_names (abfd));
      free (po_lidx_entries (abfd));
      free (po_psegm_entries (abfd));
    }

  return TRUE;
}

/* PLT and GOT stuff. See the z/Linux port for how this works. This
   is mostly the same as for z/Linux, but instead of only being able
   to use r0 and r1, we can only use r0 and r15. Also the symbol
   table offset is pushed onto the stack at 120(r13), and the
   loader ino at 112(r13).
   NOTE: Keep this in sync with the elf64-s390 version.

   z/OS TODO: Do we want to use those stack addrs?  */

static const bfd_byte po_plt_entry[32] =
  {
   0xc0, 0xf0, 0x00, 0x00, 0x00, 0x00,	    /* larl    %r15,.	       */
   0xe3, 0xf0, 0xf0, 0x00, 0x00, 0x04,	    /* lg      %r15,0(%r15)    */
   0x07, 0xff,				    /* br      %r15	       */
   0x0d, 0xf0,				    /* basr    %r15,%r0	       */
   0xe3, 0xf0, 0xf0, 0x0c, 0x00, 0x14,	    /* lgf     %r15,12(%r15)   */
   0xc0, 0xf4, 0x00, 0x00, 0x00, 0x00,	    /* jg      first plt       */
   0x00, 0x00, 0x00, 0x00		    /* .long   0x00000000      */
  };

static const bfd_byte po_first_plt_entry[32] =
  {
   0xe3, 0xf0, 0xd0, 0x78, 0x00, 0x24,	    /* stg     %r15,120(%r13)	   */
   0xc0, 0xf0, 0x00, 0x00, 0x00, 0x00,	    /* larl    %r15,.		   */
   0xd2, 0x07, 0xd0, 0x70, 0xf0, 0x08,	    /* mvc     112(8,%r13),8(%r15) */
   0xe3, 0xf0, 0xf0, 0x10, 0x00, 0x04,	    /* lg      %r15,16(%r15)	   */
   0x07, 0xff,				    /* br      %r15		   */
   0x07, 0x00,				    /* nopr    %r0		   */
   0x07, 0x00,				    /* nopr    %r0		   */
   0x07, 0x00				    /* nopr    %r0		   */
  };

/* Recognize a PIE (maybe a shared libary in the future) as a legitimate
   input file. We need to be able to link against them.  */
static bfd_boolean
po_before_object_p (bfd *abfd)
{
  bfd_byte eyecatcher[8];
  bfd_byte hdr_off_buf[4];

  if (!po_mkobject (abfd))
    return FALSE;

  /* Check for the Program Object eyecatcher.  */
  if (bfd_seek (abfd, 0, SEEK_SET) != 0
      || bfd_bread (eyecatcher, 8, abfd) != 8
      || memcmp (eyecatcher, eyecatcher_plmh, 8) != 0)
    {
      /* Bow out gracefully but don't stop processing if it isn't a PO,
	 we implicitly accept regular elf object files later.  */
      bfd_seek (abfd, 0, SEEK_SET);
      return TRUE;
    }

  /* Jump to the part of the Program Object header that points to the
     contained code.  */
  if (bfd_seek (abfd, 0x64, SEEK_SET) != 0
      || bfd_bread (hdr_off_buf, 4, abfd) != 4)
    return FALSE;

  po_elf_offset (abfd) = bfd_h_get_32 (abfd, hdr_off_buf);

  if (bfd_seek (abfd, po_elf_offset (abfd), SEEK_SET) != 0)
    return FALSE;

  /* Turn on our archive hack, this time for the read side of things.  */
  abfd->my_archive = abfd;
  abfd->origin = po_elf_offset (abfd);
  /* NOTE: arelt_data is mostly invalid, it's only there to satisfy
     a check inside _bfd_generic_get_section_contents.  */
  abfd->arelt_data = bfd_zmalloc (sizeof (struct areltdata));
  ((struct areltdata *) (abfd->arelt_data))->parsed_size =
    bfd_get_size (abfd) - po_elf_offset (abfd);

  return TRUE;
}


#ifndef HAVE_s390_elf64_vec
# error "This emulation requires s390 elf support to be built"
#endif
/* Return TRUE iff relocations for INPUT are compatible with OUTPUT.
   Allow elf64-s390 inputs to be linked to po64-s390 outputs.  */

static bfd_boolean
elf_s390_relocs_compatible (const bfd_target *input,
			    const bfd_target *output)
{
  extern const bfd_target s390_elf64_vec;
  extern const bfd_target s390_po_vec;

  return ((input == &s390_elf64_vec || input == &s390_po_vec)
	  && (output == &s390_elf64_vec || output == &s390_po_vec));
}
#define elf_backend_relocs_compatible	elf_s390_relocs_compatible

#define elf_s390x_plt_entry		po_plt_entry
#define elf_s390x_first_plt_entry	po_first_plt_entry

#define elf_backend_can_gc_sections	0  /* z/OS TODO: Remove this and
					      uncomment that line in
					      elflink.c when we fix
					      GC.  */
#define elf_backend_begin_write_processing	po_begin_write_processing
#define elf_backend_before_object_p		po_before_object_p
#define bfd_elf64_mkobject		po_mkobject
#define bfd_elf64_write_object_contents po_write_object_contents
#define bfd_elf64_bfd_final_link	po_final_link

/* Hook into the elf64_s390 relocation process by redefining a
   key function.  */
#define _bfd_final_link_relocate	po_final_link_relocate

static inline bfd_boolean
po_should_have_dyn_relocs (struct elf_link_hash_entry *h);

static inline void
po_record_got_dyn_reloc (bfd *output_bfd, asection *target_sec,
			 asection *reloc_sec, bfd_vma relocation,
			 bfd_vma off)
{
  Elf_Internal_Rela outrel;
  bfd_byte *loc;

  /* Emit ELF reloc.  */
  outrel.r_offset = (target_sec->output_section->vma
		     + target_sec->output_offset
		     + off);
  outrel.r_info = ELF64_R_INFO (0, R_390_RELATIVE);
  outrel.r_addend = relocation;
  loc = reloc_sec->contents;
  loc += reloc_sec->reloc_count++ * sizeof (Elf64_External_Rela);
  bfd_elf64_swap_reloca_out (output_bfd, &outrel, loc);

  /* Record PO reloc, to be emitted later.  */
  add_prdt_entry (output_bfd, (int) R_390_64, outrel.r_offset,
		  relocation);
}

/* Check if space should be reserved to propagate the given reloc into
   the output file.  */
#define FORCE_DYN_RELOC(info, rel)					\
  (!bfd_link_pic (info)							\
   && (ELF64_R_TYPE ((rel)->r_info) == R_390_64				\
       || ELF64_R_TYPE ((rel)->r_info) == R_390_32			\
       || ELF64_R_TYPE ((rel)->r_info) == R_390_16			\
       || ELF64_R_TYPE ((rel)->r_info) == R_390_8))

/* Check if H represents a symbol for which FORCE_DYN_RELOC is causing
   additional dynamic relocs to be generated.  */
#define SHOULD_HAVE_DYN_RELOCS(h)	po_should_have_dyn_relocs (h)

/* We define this to show that we are compiling a PDE but we will still
   be generating runtime relocs for GOT symbols that have been forced
   local.

   These kinds of relocs are generated and handled manually by special
   code in the s390 elf backend, for which using FORCE_DYN_RELOC is
   innapropriate. We need special handling for this case.  */
#define FAKE_PDE    (TRUE)

#define RECORD_GOT_DYN_RELOC(output_bfd, target_sec, reloc_sec,		\
			     relocation, off)				\
  po_record_got_dyn_reloc ((output_bfd), (target_sec), (reloc_sec),	\
			   (relocation), (off))

/* Silence some warnings.  */
#define elf_s390_mkobject		ATTRIBUTE_UNUSED elf_s390_mkobject

#define s390_elf64_vec			s390_po_vec
#define TARGET_BIG_NAME			"po64-s390"
#define bfd_elf_s390_set_options	po_set_options_dummy
#define s390_elf64_size_info		po_size_info_dummy
#include "elf64-s390.c"

/* This must come after including elf64-s390.c so we can use
   elf_s390_link_hash_entry.  */

static inline bfd_boolean
po_should_have_dyn_relocs (struct elf_link_hash_entry *h)
{
  struct elf_dyn_relocs *p;
  struct elf_s390_link_hash_entry *eh = (struct elf_s390_link_hash_entry *)h;

  if (eh == NULL)
    return FALSE;

  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      if (p->count - p->pc_count > 0)
	return TRUE;
    }

  return FALSE;
}
