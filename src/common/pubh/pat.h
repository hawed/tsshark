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

#ifndef _PAT_H_
#define _PAT_H_

#include "si_table.h"

/* parse result types of the si_parser (PAT) */

typedef struct
{
  int program_number;

  /* if program_number == 0*/
  int network_PID;

  int program_map_PID;
} TS_PAT_PROGRAM;


typedef struct 
{
  TS_SI_TABLE_SECTION stSection;

  int private_iProgramLoopLen;
  TS_PAT_PROGRAM *pastProgram;

  unsigned long CRC;

}TS_PAT;

#endif
