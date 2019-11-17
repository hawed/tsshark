/*
    Copyright (C) 2012  hawed

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef _SI_TABLE_H_
#define _SI_TABLE_H_


typedef struct
{
  char* ptr_data;
}TS_SI_BODY_SHORT;

typedef struct
{
  int table_id_extension;
  int version_number;
  int current_next_indicator;
  int section_number;
  int last_section_number;
  char* ptr_data;
}TS_SI_BODY_LONG;

typedef union
{
  TS_SI_BODY_SHORT st_body_short;    /* section_syntax_indicator == 0 */
  TS_SI_BODY_LONG st_body_long;   /* section_syntax_indicator == 1 */
 }TU_SI_TABLE_BODY;

 typedef struct
 {
   int table_id;
   int section_syntax_indicator;
   int private_indicator;
   int section_length;
 }TS_SI_TABLE_HEADER;

typedef struct 
{
  char cPointer;
  TS_SI_TABLE_HEADER stTableHeader;
  TU_SI_TABLE_BODY stTableBody;
}TS_SI_TABLE_SECTION;

#endif
