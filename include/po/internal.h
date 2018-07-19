#ifndef _PO_INTERNAL_H
#define _PO_INTERNAL_H

struct po_internal_plmh;
struct po_internal_header_rec_decl;
struct po_internal_pmar;
struct po_external_pmarl;
struct po_internal_prat_range;

struct po_internal_plmh {
  char                               fixed_eyecatcher[8];
  bfd_size_type                      length;
  unsigned char                      version;
  bfd_size_type                      uncompressed_module_size;
  unsigned int                       rec_decl_count;
  struct po_internal_header_rec_decl *rec_decls;
};

struct po_internal_header_rec_decl {
  unsigned short rec_type;
  bfd_vma        rec_offset;
  bfd_vma        rec_length;
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
  bfd_size_type  program_length_gas;
  bfd_vma        offset_text;
  bfd_vma        offset_binder_index;
  bfd_size_type  prdt_length;
  bfd_vma        prdt_offset;
  bfd_size_type  prat_length;
  bfd_vma        prat_offset;
  unsigned int   po_virtual_pages;
  bfd_size_type  ls_loader_data_length;
  /* TODO: PM2 deliniation? */
  unsigned short loadable_segment_count;
  unsigned short gas_table_entry_count;
  bfd_size_type virtual_storage_for_first_segment;
  bfd_size_type virtual_storage_for_second_segment;
  bfd_vma        offset_to_second_text_segment;
  unsigned char date_saved[4]; /* Julian packed decimal */
  unsigned char time_saved[4]; /* packed decimal hhmmss */
  unsigned char userid[8];
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
  struct po_internal_prat_range *ranges;
};

struct po_internal_prat_range {
  unsigned short begin;
  unsigned short end;
};

#endif

