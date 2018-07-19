#ifndef _PO_BFD_H
#define _PO_BFD_H

#include "po/common.h"
#include "po/internal.h"
#include "po/external.h"

#define po_tdata(bfd)  ((bfd) -> tdata.po_obj_data)
#define po_header(bfd) (po_tdata(bfd) -> header)
#define po_pmar(bfd) (po_tdata(bfd) -> pmar)
#define po_pmarl(bfd) (po_tdata(bfd) -> pmarl)

struct po_obj_tdata {
  struct po_internal_plmh  header;
  struct po_internal_pmar  pmar;
  struct po_internal_pmarl pmarl;
};

#endif
