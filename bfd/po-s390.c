#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"

struct bfd_po_section_data {
  char *contents_buffer;
  unsigned int contents_length;
};

static bfd_boolean
bfd_po_new_section_hook (bfd *abfd, sec_ptr sec)
{
  struct bfd_po_section_data *sdata;

  sdata = (struct bfd_po_section_data *) sec->used_by_bfd;
  if (sdata == NULL)
  {
    sdata = (struct bfd_po_section_data *) bfd_zalloc (abfd, sizeof(*sdata));

    if (sdata == NULL)
      return FALSE;
    sec->used_by_bfd = sdata;
  }

  return _bfd_generic_new_section_hook (abfd, sec);
}

static bfd_boolean
bfd_po_set_section_contents (bfd *abfd, sec_ptr sec, const void *contents, file_ptr offset, bfd_size_type len)
{
  // const struct bfd_po_section_data *sdata;
  // sdata = (struct bfd_po_section_data *) sec->used_by_bfd;

  printf("size %lu\n", sec->size);

  return _bfd_generic_set_section_contents(abfd, sec, contents, offset, len);
}

static bfd_boolean
bfd_po_mkobject (bfd *abfd)
{
  (void) abfd;
  /* Any initialization? */
  return TRUE;
}

static bfd_boolean
bfd_po_write_object_contents (bfd *abfd)
{
  asection *current;

  for (current = abfd->sections; current != NULL; current = current->next)
    {
      const struct bfd_po_section_data *sdata;
      printf("Section (%lu bytes):\n", current->size);
      printf("  Name: %s\n", current->name);
      printf("  Contents:\n");
      if (current->flags & SEC_HAS_CONTENTS) {
        sdata = (struct bfd_po_section_data *) current->used_by_bfd;

        for (unsigned i = 0; i < sdata->contents_length; i += 16) {
          for (unsigned i2 = i; i2 < i + 16 && i2 < sdata->contents_length; i2 ++) {
            printf("%02x", sdata->contents_buffer[i2]);
          }
          printf("\n");
        }
      } else {
        printf("    No content.\n");
      }

      printf("\n");
    }

  return TRUE;
}

const bfd_target s390_po_vec = {
  "po-s390",
  bfd_target_unknown_flavour,
  BFD_ENDIAN_BIG,
  BFD_ENDIAN_BIG,

  (BFD_RELOC_8 | BFD_RELOC_16 | BFD_RELOC_24 | BFD_RELOC_32 | EXEC_P | HAS_SYMS | WP_TEXT),
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

  _bfd_generic_close_and_cleanup,
  _bfd_generic_bfd_free_cached_info,
  bfd_po_new_section_hook,
  _bfd_generic_get_section_contents,
  _bfd_generic_get_section_contents_in_window,
  BFD_JUMP_TABLE_COPY(_bfd_generic), /* TODO? */
  BFD_JUMP_TABLE_CORE(_bfd_nocore),
  BFD_JUMP_TABLE_ARCHIVE(_bfd_noarchive), /* TODO */
  BFD_JUMP_TABLE_SYMBOLS(_bfd_nosymbols), /* TODO */
  BFD_JUMP_TABLE_RELOCS(_bfd_norelocs), /* TODO */
  _bfd_generic_set_arch_mach,
  bfd_po_set_section_contents,
  BFD_JUMP_TABLE_LINK(_bfd_nolink), /* TODO */
  BFD_JUMP_TABLE_DYNAMIC(_bfd_nodynamic),

  NULL,

  NULL
};

