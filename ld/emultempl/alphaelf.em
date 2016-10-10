# This shell script emits a C file. -*- C -*-
#   Copyright (C) 2003-2019 Free Software Foundation, Inc.
#
# This file is part of the GNU Binutils.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
# MA 02110-1301, USA.
#

# This file is sourced from elf32.em, and defines extra alpha
# specific routines.
#
fragment <<EOF

#include "elf/internal.h"
#include "elf/alpha.h"
#include "elf-bfd.h"

static bfd_boolean limit_32bit;

extern bfd_boolean elf64_alpha_use_secureplt;


/* Set the start address as in the Tru64 ld.  */
#define ALPHA_TEXT_START_32BIT 0x12000000

static void
alpha_after_open (void)
{
  if (bfd_get_flavour (link_info.output_bfd) == bfd_target_elf_flavour
      && elf_object_id (link_info.output_bfd) == ALPHA_ELF_DATA)
    {
      unsigned int num_plt;
      lang_output_section_statement_type *os;
      lang_output_section_statement_type *plt_os[2];

      num_plt = 0;
      for (os = &lang_output_section_statement.head->output_section_statement;
	   os != NULL;
	   os = os->next)
	{
	  if (os->constraint == SPECIAL && strcmp (os->name, ".plt") == 0)
	    {
	      if (num_plt < 2)
		plt_os[num_plt] = os;
	      ++num_plt;
	    }
	}

      if (num_plt == 2)
	{
	  plt_os[0]->constraint = elf64_alpha_use_secureplt ? 0 : -1;
	  plt_os[1]->constraint = elf64_alpha_use_secureplt ? -1 : 0;
	}
    }

  gld${EMULATION_NAME}_after_open ();
}

static void
alpha_after_parse (void)
{
  link_info.relax_pass = 2;
  if (limit_32bit
      && !bfd_link_pic (&link_info)
      && !bfd_link_relocatable (&link_info))
    lang_section_start (".interp",
			exp_binop ('+',
				   exp_intop (ALPHA_TEXT_START_32BIT),
				   exp_nameop (SIZEOF_HEADERS, NULL)),
			NULL);

  gld${EMULATION_NAME}_after_parse ();
}

static struct bfd_link_needed_list *force_needed_top;

static bfd_boolean
_bfd_elf_link_create_dynstrtab (bfd *abfd, struct bfd_link_info *info)
{
  struct elf_link_hash_table *hash_table;

  hash_table = elf_hash_table (info);
  if (hash_table->dynobj == NULL)
    hash_table->dynobj = abfd;

  if (hash_table->dynstr == NULL)
    {
      hash_table->dynstr = _bfd_elf_strtab_init ();
      if (hash_table->dynstr == NULL)
	return FALSE;
    }
  return TRUE;
}

static void
elf_add_dt_needed_tag (bfd *abfd,
		       struct bfd_link_info *info,
		       const char *soname,
		       bfd_boolean do_it)
{
  struct elf_link_hash_table *hash_table;
  bfd_size_type oldsize;
  bfd_size_type strindex;

  if (!_bfd_elf_link_create_dynstrtab (abfd, info))
    return;

  hash_table = elf_hash_table (info);
  oldsize = _bfd_elf_strtab_size (hash_table->dynstr);
  strindex = _bfd_elf_strtab_add (hash_table->dynstr, soname, FALSE);
  if (strindex == (bfd_size_type) -1)
    return;

  if (oldsize == _bfd_elf_strtab_size (hash_table->dynstr))
    {
      asection *sdyn;
      const struct elf_backend_data *bed;
      bfd_byte *extdyn;

      bed = get_elf_backend_data (hash_table->dynobj);
      sdyn = bfd_get_section_by_name (hash_table->dynobj, ".dynamic");
      if (sdyn != NULL)
	for (extdyn = sdyn->contents;
	     extdyn < sdyn->contents + sdyn->size;
	     extdyn += bed->s->sizeof_dyn)
	  {
	    Elf_Internal_Dyn dyn;

	    bed->s->swap_dyn_in (hash_table->dynobj, extdyn, &dyn);
	    if (dyn.d_tag == DT_NEEDED
		&& dyn.d_un.d_val == strindex)
	      {
		_bfd_elf_strtab_delref (hash_table->dynstr, strindex);
		return;
	      }
	  }
    }

  if (do_it)
    {
      if (!_bfd_elf_link_create_dynamic_sections (hash_table->dynobj, info))
	return;

      if (!_bfd_elf_add_dynamic_entry (info, DT_NEEDED, strindex))
	return;
    }
  else
    /* We were just checking for existence of the tag.  */
    _bfd_elf_strtab_delref (hash_table->dynstr, strindex);

  return;
}
static void
alpha_before_allocation (void)
{
  struct bfd_link_needed_list *entry = force_needed_top;
  while (entry) {
    elf_add_dt_needed_tag (link_info.output_bfd, &link_info, entry->name, TRUE);
    entry = entry->next;
  }
  /* Call main function; we're just extending it.  */
  gld${EMULATION_NAME}_before_allocation ();

  /* Add -relax if -O, not -r, and not explicitly disabled.  */
  if (link_info.optimize
      && !bfd_link_relocatable (&link_info)
      && ! RELAXATION_DISABLED_BY_USER)
    ENABLE_RELAXATION;
}

static void
alpha_finish (void)
{
  if (limit_32bit)
    elf_elfheader (link_info.output_bfd)->e_flags |= EF_ALPHA_32BIT;

  finish_default ();
}
EOF

# Define some shell vars to insert bits of code into the standard elf
# parse_args and list_options functions.
#
PARSE_AND_LIST_PROLOGUE='
#define OPTION_TASO		300
#define OPTION_SECUREPLT	(OPTION_TASO + 1)
#define OPTION_NO_SECUREPLT	(OPTION_SECUREPLT + 1)
#define OPTION_FORCE_ADD_NEEDED	(OPTION_NO_SECUREPLT + 1)
'

PARSE_AND_LIST_LONGOPTS='
  { "taso", no_argument, NULL, OPTION_TASO },
  { "secureplt", no_argument, NULL, OPTION_SECUREPLT },
  { "no-secureplt", no_argument, NULL, OPTION_NO_SECUREPLT },
  { "force-add-needed", required_argument, NULL, OPTION_FORCE_ADD_NEEDED },
'

PARSE_AND_LIST_OPTIONS='
  fprintf (file, _("\
  --taso                      Load executable in the lower 31-bit addressable\n\
                                virtual address range\n"));
  fprintf (file, _("\
  --secureplt                 Force PLT in text segment\n"));
  fprintf (file, _("\
  --no-secureplt              Force PLT in data segment\n"));
  fprintf (file, _("\
  --force-add-needed=<dso>    Force add needed\n"));
'

PARSE_AND_LIST_ARGS_CASES='
    case OPTION_TASO:
      limit_32bit = 1;
      break;
    case OPTION_SECUREPLT:
      elf64_alpha_use_secureplt = TRUE;
      break;
    case OPTION_NO_SECUREPLT:
      elf64_alpha_use_secureplt = FALSE;
      break;
    case OPTION_FORCE_ADD_NEEDED:
      {
        struct bfd_link_needed_list *new_entry = xmalloc (sizeof (struct bfd_link_needed_list));
	if (new_entry) {
		new_entry->name = strdup(optarg);
		new_entry->by = 0;
		new_entry->next = 0;
		struct bfd_link_needed_list *entry = force_needed_top;;
		if (entry) {
			while (entry->next)
				entry = entry->next;
			entry->next = new_entry;
		} else {
			force_needed_top = new_entry;
		}
	}
      }
      break;
'

# Put these extra alpha routines in ld_${EMULATION_NAME}_emulation
#
LDEMUL_AFTER_OPEN=alpha_after_open
LDEMUL_AFTER_PARSE=alpha_after_parse
LDEMUL_BEFORE_ALLOCATION=alpha_before_allocation
LDEMUL_FINISH=alpha_finish
