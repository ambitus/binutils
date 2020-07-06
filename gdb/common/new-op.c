/* Replace operator new/new[], for GDB, the GNU debugger.

   Copyright (C) 2016-2018 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* GCC does not understand __has_feature.  */
#if !defined(__has_feature)
# define __has_feature(x) 0
#endif

#if !__has_feature(address_sanitizer) && !defined(__SANITIZE_ADDRESS__)
#include "common-defs.h"
#include "host-defs.h"
#include <new>

/* Override operator new / operator new[], in order to internal_error
   on allocation failure and thus query the user for abort/core
   dump/continue, just like xmalloc does.  We don't do this from a
   new-handler function instead (std::set_new_handler) because we want
   to catch allocation errors from within global constructors too.

   Skip overriding if building with -fsanitize=address though.
   Address sanitizer wants to override operator new/delete too in
   order to detect malloc+delete and new+free mismatches.  Our
   versions would mask out ASan's, with the result of losing that
   useful mismatch detection.

   Note that C++ implementations could either have their throw
   versions call the nothrow versions (libstdc++), or the other way
   around (clang/libc++).  For that reason, we replace both throw and
   nothrow variants and call malloc directly.  */

void *
operator new (std::size_t sz)
{
  /* malloc (0) is unpredictable; avoid it.  */
  if (sz == 0)
    sz = 1;

  void *p = malloc (sz);	/* ARI: malloc */
  if (p == NULL)
    {
      /* If the user decides to continue debugging, throw a
	 gdb_quit_bad_alloc exception instead of a regular QUIT
	 gdb_exception.  The former extends both std::bad_alloc and a
	 QUIT gdb_exception.  This is necessary because operator new
	 can only ever throw std::bad_alloc, or something that extends
	 it.  */
      TRY
	{
	  malloc_failure (sz);
	}
      CATCH (ex, RETURN_MASK_ALL)
	{
	  do_cleanups (all_cleanups ());

#ifndef __ZOS__
	  throw gdb_quit_bad_alloc (ex);
#else
	  /* z/OS TODO: remove this case when exceptions work.  */
	  exit (99);
#endif
	}
      END_CATCH
    }
  return p;
}

void *
operator new (std::size_t sz, const std::nothrow_t&) noexcept
{
  /* malloc (0) is unpredictable; avoid it.  */
  if (sz == 0)
    sz = 1;
  return malloc (sz);		/* ARI: malloc */
}

void *
operator new[] (std::size_t sz)
{
   return ::operator new (sz);
}

void*
operator new[] (std::size_t sz, const std::nothrow_t&) noexcept
{
  return ::operator new (sz, std::nothrow);
}
#endif
