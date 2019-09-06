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

/* NOTE: Keep this structure in sync with
   the one declared in elf64-s390.c.  */
struct po_s390_obj_tdata
{
  struct elf_obj_tdata root;
  struct plt_entry *local_plt;
  char *local_got_tls_type;

  /* Program Object fields below here.  */
};

#define po_s390_tdata(abfd)				\
  ((struct po_s390_obj_tdata *) (abfd)->tdata.any)

static bfd_boolean
po_mkobject (bfd *abfd)
{
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
  BFD_ASSERT (abfd->my_archive == NULL);
  abfd->my_archive = abfd;
  //abfd->origin = po_s390_tdata (abfd)->po_header_size;
  abfd->origin = 0x1000 * 50;	/* TODO.  */
  abfd->arelt_data = bfd_zmalloc (sizeof (struct areltdata));
  if (abfd->arelt_data == NULL)
    abort ();
  ((struct areltdata *) (abfd->arelt_data))->parsed_size = bfd_get_size (abfd);
}

/* Add an entry to the PRDT, which will cause the loader to resolve
   the given absolute relocation at load-time. The relocation, described
   by RELENT, is located at OFFSET from the start of the module.  */

static bfd_boolean
add_prdt_entry (bfd *abfd, bfd_vma offset, arelent *reloc)
{
  bfd_vma addend;
  unsigned int curr;
  struct po_internal_relent *entry;
  bfd_size_type page = offset / 0x1000;
  asymbol *symbol = *reloc->sym_ptr_ptr;
  bfd_boolean no_cksum = FALSE;

  if (symbol == NULL)
    return FALSE;

  if (page_number > 4294967295)
    {
      _bfd_error_handler
	/* xgettext:c-format */
	(_("Page number for reloc is unrepresentable (%lu)"), page_number);
      bfd_set_error (bfd_error_file_too_big);
      return FALSE;
    }

  unsigned int pgs = po_prat (abfd).total_entries;

  /* Grow the page entry array if needed.  */
  if (pgs < page + 2)
    {
      unsigned int new_pgs = (page + 5) * 3 / 2;

      po_prdt_pages (abfd) =
	bfd_realloc2 (new_total, sizeof (struct po_internal_prdt_page));
      if (po_prdt_pages (abfd) == NULL)
	return FALSE;

      for (unsigned int pg = pgs; pg <= new_pgs; ++pg)
	{
	  struct po_internal_prdt_page *p = &po_prdt_pages (abfd)[pg];
	  p->num = pg;
	  p->seg_idx = 1;
	  p->checksum[0] = p->checksum[1] =
	    p->checksum[2] =  p->checksum[3] = 0;
	  p->count = 0;
	  p->no_checksum = FALSE;
	  p->relocs = NULL;
	}
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

  /* TODO: conditionalize symbol->value? */
  addend = (symbol->section->output_section->vma
	    + symbol->section->output_offset
	    + reloc->addend + symbol->value);

  /* Figure out which type of reloc we should use.  */
  switch (reloc->howto->type)
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

/* Special PO relocation processing.

   z/OS TODO: This is a bit inefficient, but to do better we would need
   our own howto table, which is possible.

   z/OS TODO: we need to forbit pc-relative weak relocs (because they are
   unimplementable).  */

static bfd_reloc_status_type
po_reloc (bfd *abfd, arelent *reloc_entry, asymbol *symbol,
	  void *data, asection *input_section, bfd *output_bfd,
	  char **error_message)
{
  bfd_vma full_offset;
  reloc_howto_type *howto = reloc_entry->howto;

  if (howto == NULL)
    return bfd_reloc_undefined;

  if (!howto->type
      && bfd_is_abs_section (symbol->section))
    return bfd_reloc_continue;

  switch (howto->type)
    {
    case R_390_32:
    case R_390_64:
      full_offset = (input_section->output_offset + symbol->vma
		     + reloc_entry->address);
      add_prdt_entry (abfd, full_offset, reloc_entry);
      return bfd_reloc_cont;

    default:
      return bfd_elf_generic_reloc (abfd, reloc_entry, symbol, data,
				    input_section, output_bfd,
				    error_message);
    }
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

  unsigned int pages_needed =
    ROUND_UP (po_text_length (abfd), 0x1000) / 0x1000;

  po_rec_decls (abfd)[rec_num++] = (struct po_internal_header_rec_decl) {
    .rec_type = PLMH_REC_TYPE_PRAT,
    .rec_offset = file_pos,
    .rec_length = po_prat(abfd).length
  };

  /* Advance past PRAT */
  bfd_vma base = (PRAT_BASE_SIZE + (pages_needed + 1) * PRAT_ENTRY_SIZE);
  po_prat_pad_bytes (abfd) = po_prat (abfd).length - base;
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
      char *start;
      unsigned int entries = po_prdt_page_headers (abfd)[page].count;
      bfd_vma page_rel_size = PRDT_PAGE_HEADER_SIZE;
      bfd_boolean found32 = FALSE, found64 = FALSE;

      if (entries == 0)
	{
	  po_prat_entries (abfd)[page] = 0;
	  continue;
	}
      start = (po_section_contents (abfd) + page * 0x1000);

      if (!po_prdt_page_headers (abfd)[page].no_checksum)
	memcpy (po_prdt_page_headers (abfd)[page].checksum, start, 4);
      po_prat_entries (abfd)[page] = prdt_pos;

      for (unsigned int ent_num = 0; ent_num < entries; ent_num++)
	{
	  switch (po_prdt_entries (abfd)[page][ent_num].type)
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

  /* This is the size of po_prdt_page_headers.  */
  po_prat (abfd).total_entries = 0;

  /* FIXME: These grow, and we never free them.  */
  po_prdt_pages (abfd) = NULL;
  if (po_prdt_pages (abfd) == NULL)
    return FALSE;

  po_prat_entries (abfd) = NULL;
  if (po_prat_entries (abfd) == NULL)
    return FALSE;

  /* Invoke the regular ELF backend linker.  */
  if (!bfd_elf_final_link (abfd, info))
    return FALSE;
}

#define elf_backend_begin_write_processing	po_begin_write_processing
#define bfd_elf64_mkobject		po_mkobject

#define bfd_elf_generic_reloc		po_reloc
#define elf_s390_mkobject		__attribute__ ((used)) elf_s390_mkobject

#define s390_elf64_vec			s390_po_vec
#define TARGET_BIG_NAME			"po64-s390"
#define bfd_elf_s390_set_options	po_set_options_dummy
#define s390_elf64_size_info		po_size_info_dummy
#include "elf64-s390.c"
