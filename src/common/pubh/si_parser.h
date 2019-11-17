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

#ifndef _SI_PARSER_H_
#define _SI_PARSER_H_

#include "pat.h"
#include "pmt.h"
#include "cat.h"
#include "nit.h"
#include "bat.h"
#include "pat.h"
#include "sdt.h"
#include "eit.h"
#include "rst.h"
#include "tdt.h"
#include "tot.h"
#include "st.h"

typedef enum 
{
  eSI_PARSER_OK,
  eSI_PARSER_INCOMPLETE,
  eSI_PARSER_NOT_FOUND,
  eSI_PARSER_ERROR
}TE_SI_PARSER_RC;

typedef int T_SI_PARSER_HANDLE;
#define SI_PARSER_INVALID (T_SI_PARSER_HANDLE)-1;

typedef enum
{
  ePARSER_PAT,
  ePARSER_PMT, 
  ePARSER_CAT,
  ePARSER_NIT,
  ePARSER_BAT,
  ePARSER_SDT,
  ePARSER_EIT,
  ePARSER_RST,
  ePARSER_TDT,
  ePARSER_TOT,
  ePARSER_ST
}TE_PARSER_TYPE;

TE_SI_PARSER_RC  si_parser_e_create(T_SI_PARSER_HANDLE  *pHandle, TE_PARSER_TYPE eType);
TE_SI_PARSER_RC  si_parser_e_destroy(T_SI_PARSER_HANDLE  tHandle);


/*
**  returns OK                         
**  returns INCOMPLETE if an incomplete section was found at the end of pabInputBuf
**                a following parse call will get the packet data if a new buffer is attached
*/
TE_SI_PARSER_RC  si_parser_e_parse_pat(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_PAT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_pat(TS_PAT *pstParseResult);



TE_SI_PARSER_RC  si_parser_e_parse_pmt(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen, 
                                       int iPid, 
                                       TS_PMT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_pmt(TS_PMT *pstParseResult);


TE_SI_PARSER_RC  si_parser_e_parse_cat(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_CAT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_cat(TS_CAT *pstParseResult);

TE_SI_PARSER_RC  si_parser_e_parse_nit(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_NIT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_nit(TS_NIT *pstParseResult);

TE_SI_PARSER_RC  si_parser_e_parse_bat(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_BAT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_bat(TS_BAT *pstParseResult);

TE_SI_PARSER_RC  si_parser_e_parse_sdt(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_SDT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_sdt(TS_SDT *pstParseResult);

TE_SI_PARSER_RC  si_parser_e_parse_eit(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_EIT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_eit(TS_EIT *pstParseResult);

TE_SI_PARSER_RC  si_parser_e_parse_rst(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_RST *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_rst(TS_RST *pstParseResult);

TE_SI_PARSER_RC  si_parser_e_parse_tdt(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_TDT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_tdt(TS_TDT *pstParseResult);

TE_SI_PARSER_RC  si_parser_e_parse_tot(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_TOT *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_tot(TS_TOT *pstParseResult);

TE_SI_PARSER_RC  si_parser_e_parse_st(T_SI_PARSER_HANDLE  tHandle, 
                                      char* pabInputBuffer, 
                                      unsigned long uwBufferLen,  
                                      TS_ST *pstParseResult);
TE_SI_PARSER_RC  si_parser_e_free_st(TS_ST *pstParseResult);

#endif


