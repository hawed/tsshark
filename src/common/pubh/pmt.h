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

#ifndef _PMT_H_
#define _PMT_H_


#include "si_table.h"

typedef struct
{
  int stream_type;
  int elementary_PID;

  int ES_info_length;
  char *pDescriptorDataEsInfo; //ptr to section buffer -> use descriptor_parser!! TODO

}TS_PMT_STREAM;

typedef struct 
{
  TS_SI_TABLE_SECTION stSection;

  int PCR_PID;

  int program_info_length;
  char *pDescriptorDataProgramInfo; //ptr to section buffer -> use descriptor_parser!! TODO
    
  int private_iStreamLoopLen; //private var
  TS_PMT_STREAM *pastStream;
    
  unsigned long CRC;

}TS_PMT;

#endif
