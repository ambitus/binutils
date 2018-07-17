#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"

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
  (void) abfd;
  /* TODO */
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

  BFD_JUMP_TABLE_GENERIC(_bfd_generic), /* TODO? */
  BFD_JUMP_TABLE_COPY(_bfd_generic), /* TODO? */
  BFD_JUMP_TABLE_CORE(_bfd_nocore),
  BFD_JUMP_TABLE_ARCHIVE(_bfd_noarchive), /* TODO */
  BFD_JUMP_TABLE_SYMBOLS(_bfd_nosymbols), /* TODO */
  BFD_JUMP_TABLE_RELOCS(_bfd_norelocs), /* TODO */
  BFD_JUMP_TABLE_WRITE(_bfd_generic),
  BFD_JUMP_TABLE_LINK(_bfd_nolink), /* TODO */
  BFD_JUMP_TABLE_DYNAMIC(_bfd_nodynamic),

  NULL,

  NULL
};

