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

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#include "pubh/si_parser.h"
#include "pubh/ts_parser.h"
#include "pubh/output.h"

#define TRACE_IF(x)          //printf x         
#define TRACE_CALLS(x) //printf x
#define TRACE_PARSE(x) printf x

#define USE_HEXDUMPS (1)

#define TRACE_ERR printf("E: %s: %i\n", __FILE__,__LINE__); 

#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0) 

#define MAX_SI_PARSER (15)
#define MAX_SECTIONS (4)
#define SECTION_SIZE_SHORT (1024)
#define SECTION_SIZE_LONG   (4* 1024)

#define PARSE_NOT_FOUND_THRESHOLD (16*1024) //TS packets test !! increase later

#define PID_PAT 0x00 
#define PID_PMT_MIN 0x20 
#define PID_PMT_MAX 0x1FFE 
#define PID_CAT 0x01 
#define PID_NIT 0x10 
#define PID_BAT 0x11 
#define PID_SDT 0x11 
#define PID_EIT 0x12
#define PID_RST 0x13
#define PID_TDT 0x14 
#define PID_TOT 0x14 

#define TID_PAT 0x00 
#define TID_PMT 0x02 
#define TID_CAT 0x01 
#define TID_NIT1 0x40 
#define TID_NIT2 0x41 
#define TID_BAT 0x4A 
#define TID_SDT1 0x42 
#define TID_SDT2 0x46 
#define TID_EIT_MIN 0x4E
#define TID_EIT_MAX 0x6F
#define TID_RST 0x71
#define TID_TDT 0x70
#define TID_TOT 0x73
#define TID_ST 0x72

static pthread_mutex_t  _tMutexParserTable = PTHREAD_MUTEX_INITIALIZER;


#define LOCK_PARSER_TABLE       {if(pthread_mutex_lock(&_tMutexParserTable)) {TRACE_ERR;}}
#define UNLOCK_PARSER_TABLE {if(pthread_mutex_unlock(&_tMutexParserTable)) {TRACE_ERR;}}


#define LOCK_PARSER_BY_HANDLE(handle)       {if(pthread_mutex_lock(&_astParser[handle].tMutexParser)) {TRACE_ERR;}}
#define UNLOCK_PARSER_BY_HANDLE(handle) {if(pthread_mutex_unlock(&_astParser[handle].tMutexParser)) {TRACE_ERR;}}


typedef enum
{
  ePARSER_IDLE,
  ePARSER_PARSING
} TE_PARSER_STATE;

typedef struct
{
  unsigned long uwCallerContext;
  TE_PARSER_STATE eState;
  TE_PARSER_TYPE eType;
  unsigned long uwSectionBufferWritePtr;
  T_TS_PARSER_HANDLE tTsParserHandle;
  unsigned long uwPacketCount;
  int iSectionBufferSize;
  int iSectionComplete;
  int iSectionLen;
  char *pSectionBuffer;
  char *pSectionStart; 
  char *pSectionWrite;
  char *pSectionRead;;

  pthread_mutex_t tMutexParser;

} TS_PARSER;

static TS_PARSER _astParser[MAX_SI_PARSER];

static int _bIsFirstCreation = 1;


/*
** private 
*/
static void _initParserData(void);
static TE_SI_PARSER_RC _eGetFreeHandle(T_SI_PARSER_HANDLE *pHandle);
static int _mallocSections(T_SI_PARSER_HANDLE tHandle, int iSize);
static void _freeSections(T_SI_PARSER_HANDLE tHandle);
static TE_SI_PARSER_RC _getSections2(T_SI_PARSER_HANDLE tHandle, char* pBuf, unsigned long uwLen, int iPid, int *piRealloc);
static TE_SI_PARSER_RC _getFirstPacketOfSection(T_SI_PARSER_HANDLE tHandle,  TS_PACKET_DATA *pstTsParseResult, int *piRealloc);
static TE_SI_PARSER_RC _getPacketOfSection(T_SI_PARSER_HANDLE tHandle,  TS_PACKET_DATA *pstTsParseResult);
static int _isValidTableId(int iTableId, TE_PARSER_TYPE eType);
static int _isValidSectionLen(int iSectionLen, TE_PARSER_TYPE eType);

static void _getHeader(char* pRead,  TS_SI_TABLE_HEADER *pstParseResult);
static void _getBody(char* pRead,  TU_SI_TABLE_BODY *pstParseResult);

static TE_SI_PARSER_RC  _parserParsePAT(T_SI_PARSER_HANDLE tHandle, TS_PAT *pstResult /*OUT*/); 
static TE_SI_PARSER_RC  _parserParsePMT(T_SI_PARSER_HANDLE tHandle, TS_PMT *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseCAT(T_SI_PARSER_HANDLE tHandle, TS_CAT *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseNIT(T_SI_PARSER_HANDLE tHandle, TS_NIT *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseBAT(T_SI_PARSER_HANDLE tHandle, TS_BAT *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseSDT(T_SI_PARSER_HANDLE tHandle, TS_SDT *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseEIT(T_SI_PARSER_HANDLE tHandle, TS_EIT *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseRST(T_SI_PARSER_HANDLE tHandle, TS_RST *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseTDT(T_SI_PARSER_HANDLE tHandle, TS_TDT *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseTOT(T_SI_PARSER_HANDLE tHandle, TS_TOT *pstResult/*OUT*/);
static TE_SI_PARSER_RC  _parserParseST(T_SI_PARSER_HANDLE tHandle, TS_ST *pstResult/*OUT*/);

/*
** API
*/
TE_SI_PARSER_RC  si_parser_e_create(T_SI_PARSER_HANDLE  *pHandle, TE_PARSER_TYPE eType)
{
  TE_SI_PARSER_RC eRc = eTS_PARSER_OK;

  TRACE_IF(("si_parser_e_create\n"));

  if (pHandle == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_TABLE;

  if (_bIsFirstCreation == 1)
  {
    _initParserData();
    _bIsFirstCreation = 0;
  }

  if (_eGetFreeHandle(pHandle))
  {
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    _astParser[*pHandle].tTsParserHandle = TS_PARSER_INVALID;
    if (ts_parser_e_create(&_astParser[*pHandle].tTsParserHandle))
    {
      TRACE_ERR;
      eRc = eSI_PARSER_ERROR;
    }
    else
    {
      _astParser[*pHandle].uwCallerContext = 17; // (unsigned long)pthread_self(); DOESNT'WORK
      _astParser[*pHandle].eState = ePARSER_IDLE;
      _astParser[*pHandle].eType = eType;
      _astParser[*pHandle].pSectionBuffer = NULL;
      _astParser[*pHandle].pSectionStart = NULL;
      _astParser[*pHandle].iSectionBufferSize = 0;
      _astParser[*pHandle].iSectionComplete = 0; 
      _astParser[*pHandle].uwPacketCount = 0;
      pthread_mutex_init(&_astParser[*pHandle].tMutexParser, NULL);
    }
  }

  UNLOCK_PARSER_TABLE;

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_destroy(T_SI_PARSER_HANDLE  tHandle)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_destroy\n"));

  if (tHandle >= MAX_SI_PARSER)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  LOCK_PARSER_TABLE;

  _astParser[tHandle].uwCallerContext = (unsigned long)NULL;
  _astParser[tHandle].eState = ePARSER_IDLE;
  _astParser[tHandle].uwPacketCount = 0;

  if (_astParser[tHandle].tTsParserHandle != TS_PARSER_INVALID)
  {
    if (ts_parser_e_destroy(_astParser[tHandle].tTsParserHandle))
    {
      TRACE_ERR;
    }
  }
  _astParser[tHandle].tTsParserHandle = TS_PARSER_INVALID;

  _astParser[tHandle].iSectionBufferSize = 0;
  _astParser[tHandle].iSectionComplete = 0; 
  
  /* just to be sure*/
  _freeSections(tHandle);

  pthread_mutex_destroy(&_astParser[tHandle].tMutexParser);

  UNLOCK_PARSER_TABLE;

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_pat(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_PAT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define PAT_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_pat\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_PAT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_PAT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (PAT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_PAT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParsePAT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_pat(TS_PAT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_pat\n"));

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastProgram != NULL)
  {
    free(pstParseResult->pastProgram);
    pstParseResult->pastProgram = NULL;
  }

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_pmt(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,
                                       int iPid,  
                                       TS_PMT *pstParseResult)
{
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define PMT_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_pmt\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_PMT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_PAT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (PMT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, iPid, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParsePMT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_pmt(TS_PMT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_pmt\n"));

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastStream != NULL)
  {
    free(pstParseResult->pastStream);
    pstParseResult->pastStream = NULL;
  }

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_cat(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_CAT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define CAT_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_cat\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_CAT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_CAT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (CAT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_CAT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseCAT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_cat(TS_CAT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_cat\n"));

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  return eRc;
}


TE_SI_PARSER_RC  si_parser_e_parse_nit(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_NIT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define NIT_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_nit\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_NIT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_NIT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (NIT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_NIT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseNIT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_nit(TS_NIT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_nit\n"));

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastTransportStream != NULL)
  {
    free(pstParseResult->pastTransportStream);
    pstParseResult->pastTransportStream = NULL;
  }

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_bat(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_BAT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define BAT_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_bat\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_BAT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_BAT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (BAT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_BAT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseBAT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_bat(TS_BAT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_bat\n"));

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastTransportStream != NULL)
  {
    free(pstParseResult->pastTransportStream);
    pstParseResult->pastTransportStream = NULL;
  }

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_sdt(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_SDT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define SDT_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_sdt\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_SDT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_SDT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (SDT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_SDT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseSDT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_sdt(TS_SDT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_sdt\n"));

#if 0
  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastProgram != NULL)
  {
    free(pstParseResult->pastProgram);
    pstParseResult->pastProgram = NULL;
  }
#endif

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_eit(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_EIT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define EIT_SECTION_SIZE_MAX (SECTION_SIZE_LONG + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_eit\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_EIT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_EIT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (EIT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_EIT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseEIT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_eit(TS_EIT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_eit\n"));

#if 0
  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastProgram != NULL)
  {
    free(pstParseResult->pastProgram);
    pstParseResult->pastProgram = NULL;
  }
#endif

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_rst(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_RST *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define RST_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_rst\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_RST)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_RST));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (RST_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_RST, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseRST(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_rst(TS_RST *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_rst\n"));

#if 0
  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastProgram != NULL)
  {
    free(pstParseResult->pastProgram);
    pstParseResult->pastProgram = NULL;
  }
#endif

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_tdt(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_TDT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define TDT_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_tdt\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_TDT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_TDT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (TDT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_TDT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseTDT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_tdt(TS_TDT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_tdt\n"));

#if 0
  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastProgram != NULL)
  {
    free(pstParseResult->pastProgram);
    pstParseResult->pastProgram = NULL;
  }
#endif

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_tot(T_SI_PARSER_HANDLE  tHandle, 
                                       char* pabInputBuffer, 
                                       unsigned long uwBufferLen,  
                                       TS_TOT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define TOT_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_tot\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_TOT)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_TOT));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (TOT_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_TOT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseTOT(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_tot(TS_TOT *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_tot\n"));

#if 0
  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastProgram != NULL)
  {
    free(pstParseResult->pastProgram);
    pstParseResult->pastProgram = NULL;
  }
#endif

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_parse_st(T_SI_PARSER_HANDLE  tHandle, 
                                      char* pabInputBuffer, 
                                      unsigned long uwBufferLen,  
                                      TS_ST *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

#define ST_SECTION_SIZE_MAX (SECTION_SIZE_SHORT + (1 * TS_PACKET_SIZE/* ptr field offset */)) 

  TRACE_IF(("si_parser_e_parse_st\n"));

  if ((tHandle >= MAX_SI_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if (_astParser[tHandle].eType != ePARSER_ST)
  {
    /* wrong parser for this table*/
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  LOCK_PARSER_BY_HANDLE(tHandle);

  memset(pstParseResult, 0, sizeof(TS_ST));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }
  else
  {
    int iNumberOfSections = 1;
    int iRealloc = 0;

    while (1) /* section loop */
    {
      /* if there is no section buffer so far - create one */
      if (_astParser[tHandle].pSectionBuffer == NULL)
      {
        if (_mallocSections(tHandle,  (ST_SECTION_SIZE_MAX * iNumberOfSections)))
        {
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }
      }

      /* fill the section buffer if not done yet */
      if (_astParser[tHandle].iSectionComplete == 0)
      {
        eRc =  _getSections2(tHandle, pabInputBuffer, uwBufferLen, PID_PAT, &iRealloc);

        if(eRc == eSI_PARSER_ERROR)
        {
          TRACE_ERR;
        }
      }

      /* parse the filled section buffer*/
      if (_astParser[tHandle].iSectionComplete == 1)
      {
        eRc = _parserParseST(tHandle, pstParseResult); 

        if (eRc != eSI_PARSER_OK)
        {
          if (eRc == eSI_PARSER_ERROR )
          {
            TRACE_ERR;
          }
        }
      }

      if (iRealloc == 1)
      {
        /*data is bigger than one section buffer - just start again*/
        iNumberOfSections += 1;

        _freeSections(tHandle);

        if (iNumberOfSections > MAX_SECTIONS)
        {
          /* something is really wrong */
          TRACE_ERR;
          eRc =  eSI_PARSER_ERROR;
          break;
        }

        /* now realloc */
        continue;
      }

      break;
    } //section loop
  }

  UNLOCK_PARSER_BY_HANDLE(tHandle);

  return eRc;
}

TE_SI_PARSER_RC  si_parser_e_free_st(TS_ST *pstParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;

  TRACE_IF(("si_parser_e_free_st\n"));

#if 0
  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstParseResult->pastProgram != NULL)
  {
    free(pstParseResult->pastProgram);
    pstParseResult->pastProgram = NULL;
  }
#endif

  return eRc;
}

/*
** private
*/
static void _initParserData(void)
{
  TRACE_CALLS(("_initParserData\n"));
  
  memset(_astParser, 0,  sizeof(TS_PARSER) * MAX_SI_PARSER );
}

static TE_SI_PARSER_RC _eGetFreeHandle(T_SI_PARSER_HANDLE *pHandle)
{
  TE_SI_PARSER_RC eRc = eTS_PARSER_ERROR;
  int i;

  TRACE_CALLS(("_eGetFreeHandle\n"));

  if (pHandle == NULL)
  {
    TRACE_ERR;
    return eRc;
  }

  *pHandle =SI_PARSER_INVALID;

  for (i = 0; i < MAX_SI_PARSER; i++)
  {
    if (_astParser[i].uwCallerContext == 0 )
    {
      *pHandle = (T_SI_PARSER_HANDLE)i;
      eRc = eSI_PARSER_OK;
      break;
    }
  }

  return eRc;
}

static int _mallocSections(T_SI_PARSER_HANDLE tHandle, int iSize)
{
  int iRc = 0;

  TRACE_CALLS(("_mallocSections\n"));

  if (tHandle >= MAX_SI_PARSER)
  {
    TRACE_ERR;
    return -1;
  }
  /* allocate memory for at least one section */
  _astParser[tHandle].pSectionBuffer = (char*)malloc((size_t)iSize);

  if (_astParser[tHandle].pSectionBuffer == NULL)
  {
    TRACE_ERR;
    return -1;
  }
  memset( _astParser[tHandle].pSectionBuffer, 0, (size_t)iSize);
  _astParser[tHandle].iSectionBufferSize = iSize;

  return iRc;
}

static void _freeSections(T_SI_PARSER_HANDLE tHandle)
{
  TRACE_CALLS(("_freeSections\n"));

  if (tHandle >= MAX_SI_PARSER)
  {
    TRACE_ERR;
    return;
  }
  if (_astParser[tHandle].pSectionBuffer != NULL)
  {
    free(_astParser[tHandle].pSectionBuffer);
    _astParser[tHandle].pSectionBuffer = NULL;
  }
  _astParser[tHandle].iSectionBufferSize = 0;

  return;
}

static int _isValidTableId(int iTableId, TE_PARSER_TYPE eType)
{
   switch (eType)
  {
  case ePARSER_PAT: return (!!(iTableId == TID_PAT));
  case ePARSER_PMT: return (!!(iTableId == TID_PMT));
  case ePARSER_CAT: return (!!(iTableId == TID_CAT));
  case ePARSER_NIT: return ((!!(iTableId == TID_NIT1)) || (!!(iTableId == TID_NIT2)));
  case ePARSER_BAT: return (!!(iTableId == TID_BAT));
  case ePARSER_SDT: return ((!!(iTableId == TID_SDT1)) || (!!(iTableId == TID_SDT2)));
  case ePARSER_EIT: return ((!!(iTableId > TID_EIT_MIN)) && (!!(iTableId < TID_EIT_MAX))); 
  case ePARSER_RST: return (!!(iTableId == TID_RST));
  case ePARSER_TDT: return (!!(iTableId == TID_TDT));
  case ePARSER_TOT: return (!!(iTableId == TID_TOT));
  case ePARSER_ST: return (!!(iTableId == TID_ST));

  default: TRACE_ERR; return 0;
  }
}

static int _isValidSectionLen(int iSectionLen, TE_PARSER_TYPE eType)
{
  int iRc = 0; //not valid

  if (eType == ePARSER_EIT)
  {
    iRc = !!(iSectionLen < (SECTION_SIZE_LONG - 3)); 
  }
  else
  {
    iRc = !!(iSectionLen < (SECTION_SIZE_SHORT - 3)); 
  }
  return iRc;
}

static TE_SI_PARSER_RC _getFirstPacketOfSection(T_SI_PARSER_HANDLE tHandle,  TS_PACKET_DATA *pstTsParseResult, int *piRealloc)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  TS_SI_TABLE_HEADER stTableHeader;
  char cOffset = 1;
  int iToRead = 0;

  TRACE_CALLS(("_getFirstPacketOfSection\n"));

  if ((tHandle >= MAX_SI_PARSER) ||  (piRealloc == NULL) || (pstTsParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(pstTsParseResult->iPayloadLen < 4/* ptr + table id + flags + section lenght*/ )
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

   /* to be save*/
  *piRealloc = 0;
  _astParser[tHandle].iSectionComplete = 0;
  _astParser[tHandle].pSectionWrite  =  NULL;
  memset(&stTableHeader, 0, sizeof(TS_SI_TABLE_HEADER));

  /*  ptr field */
  cOffset+= pstTsParseResult->pabPayload[0] & 0xff;

  TRACE_PARSE(("si_parser: ptr field [0x%02x]\n",cOffset-1));

   /* preparse table header to get section len information */
  TRACE_PARSE(("si_parser: preparse table header\n"));

  _getHeader(pstTsParseResult->pabPayload + cOffset,  &stTableHeader);

  if(_isValidTableId(stTableHeader.table_id, _astParser[tHandle].eType) == 0)
  {
    return eSI_PARSER_NOT_FOUND;;
  }

  if(_isValidSectionLen(stTableHeader.section_length, _astParser[tHandle].eType) == 0)
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR; //corrupt data 
  }
  else
  {
    /*check if our buffer is sufficiant*/
    if ((stTableHeader.section_length + cOffset + 3/*table header*/) > _astParser[tHandle].iSectionBufferSize)
    {
      /* our section buffer is too small for one section - parsing not possible reallocate buffer first*/
      _astParser[tHandle].iSectionComplete = 0;  
      *piRealloc = 1;
      return eSI_PARSER_OK;
    }

    /* store the section len*/
    _astParser[tHandle].iSectionLen = stTableHeader.section_length;
    
    if((stTableHeader.section_length + cOffset + 3/*table header*/) > pstTsParseResult->iPayloadLen)
    {
      iToRead = pstTsParseResult->iPayloadLen;
    }
    else
    {
      iToRead = stTableHeader.section_length + cOffset + 3/*table header*/;
    }

    /*store the first payload*/
    memcpy(_astParser[tHandle].pSectionBuffer, pstTsParseResult->pabPayload, (size_t)iToRead);
    _astParser[tHandle].pSectionWrite = _astParser[tHandle].pSectionBuffer + iToRead;
        

    /* set up ptr*/
    _astParser[tHandle].pSectionStart  = _astParser[tHandle].pSectionBuffer + cOffset + 3/* ptr + table id + flags + section lenght*/;
    _astParser[tHandle].pSectionRead = _astParser[tHandle].pSectionStart; 

    /* len < (1 * TS packet)*/
    if ((stTableHeader.section_length + cOffset + 3) <= (TS_PACKET_SIZE - 4/*header*/))
    {
      /*  everything read into section buffer */
      TRACE_PARSE(("si_parser: section complete with first packet\n"));
      _astParser[tHandle].iSectionComplete = 1; 
    }

    /* (1 * TS packet) < len < section_buffer_size - !!most likely!! */
    if (((stTableHeader.section_length + cOffset + 3) > (TS_PACKET_SIZE - 4/*header*/)) && 
        ((stTableHeader.section_length + cOffset + 3) < _astParser[tHandle].iSectionBufferSize))
    {
      /* we need to read more ts packets to complete the section */
      TRACE_PARSE(("si_parser: section not complete with first packet\n"));
      _astParser[tHandle].iSectionComplete = 0;  
    }
  }//valid len

  return eRc;
}

static TE_SI_PARSER_RC _getPacketOfSection(T_SI_PARSER_HANDLE tHandle,  TS_PACKET_DATA *pstTsParseResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  int iToRead = 0;


  if ((tHandle >= MAX_SI_PARSER) || (pstTsParseResult == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  TRACE_CALLS(("_getPacketOfSection\n"));

  /* watch out ( PUSI == 1) + (ptr != 0) is a special case*/
  if((pstTsParseResult->stHeader.payload_unit_start_indicator == 1) &&
     (pstTsParseResult->pabPayload[0] & 0xff ) != 0)
  {
    TRACE_PARSE(("si_parser: found section data of old section within new PUSI packet TODO!\n"));

    //tbd
  }
  else
  {
    /* determine how much data is missing*/
    iToRead = _astParser[tHandle].iSectionLen - (_astParser[tHandle].pSectionWrite - _astParser[tHandle].pSectionStart);

    if(iToRead > pstTsParseResult->iPayloadLen)
    {
      iToRead = pstTsParseResult->iPayloadLen;
    }
    else
    {
      _astParser[tHandle].iSectionComplete = 1;
    }
    
    TRACE_PARSE(("si_parser: read %i  byte of packet data\n",iToRead));

    /* store*/
    memcpy(_astParser[tHandle].pSectionWrite,  pstTsParseResult->pabPayload,  iToRead);

    _astParser[tHandle].pSectionWrite += iToRead;
  }

  return eRc;
}

static TE_SI_PARSER_RC _getSections2(T_SI_PARSER_HANDLE tHandle, char* pBuf, unsigned long uwLen, int iPid, int *piRealloc)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  TE_TS_PARSER_RC eTsRc = eTS_PARSER_OK;
  TS_PACKET_DATA stTsParseResult;
  unsigned long uwPacketCount = 0;

  TRACE_CALLS(("_getSections [pid: %i]\n",iPid));

  if ((tHandle >= MAX_SI_PARSER) || (pBuf == NULL) || (uwLen == 0) || (piRealloc == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  memset(&stTsParseResult, 0, sizeof(TS_PACKET_DATA));

  /* assume a section will fit into our buf */
  *piRealloc = 0;

  uwPacketCount = _astParser[tHandle].uwPacketCount;

  /* start filling the section buffer */
  while (1)
  {
    eTsRc = ts_parser_e_parse(_astParser[tHandle].tTsParserHandle, 
                              pBuf,
                              uwLen,
                              0,
                              &stTsParseResult);

    if (eTsRc == eTS_PARSER_OK)
    {
      uwPacketCount++;

      if ((_astParser[tHandle].pSectionWrite == NULL) &&
          (stTsParseResult.stHeader.payload_unit_start_indicator == 1) &&
          (stTsParseResult.stHeader.PID == iPid))
      {
        TRACE_PARSE(("\nsi_parser: found PUSI pid:%i%s\n",iPid,pidToStr(iPid)));
  
        if(_getFirstPacketOfSection(tHandle, &stTsParseResult,  piRealloc))
        {
          continue; //try next packet
        }
#if USE_HEXDUMPS
        printf("***FIRST PACKET***\n");
        hexOut(stTsParseResult.pabPayload,  stTsParseResult.iPayloadLen);
        printf("***END FIRST PACKET***\n");
#endif
      }  
      else if ((_astParser[tHandle].pSectionWrite != NULL) &&
                   (_astParser[tHandle].iSectionComplete == 0) &&  
                   (stTsParseResult.stHeader.PID == iPid))
      {
        TRACE_PARSE(("\nsi_parser: found payload of pid:%i%s\n",iPid,pidToStr(iPid)));

         if(_getPacketOfSection(tHandle, &stTsParseResult))
         {
           TRACE_ERR;
           continue; //try next packet
         }
#if USE_HEXDUMPS
        printf("***PACKET PAYLOAD***\n");
        hexOut(stTsParseResult.pabPayload,  stTsParseResult.iPayloadLen);
        printf("***END PACKET***\n");
#endif
      }
      else
      {
        TRACE_PARSE(("."));
      }
    }
    else //ts parser rc != ok
    {
      if (eTsRc == eTS_PARSER_ERROR)
      {
        TRACE_ERR;
        _astParser[tHandle].iSectionComplete    = 0;
        uwPacketCount = 0;
        eRc = eSI_PARSER_ERROR;
      }
      
      break;
    }

    if(_astParser[tHandle].iSectionComplete == 1)
    {
      /* we have evrething we need */
      TRACE_PARSE(("si_parser: section complete\n"));
      break;
    }

    if (uwPacketCount >= PARSE_NOT_FOUND_THRESHOLD)
    {
      /*not found */
      TRACE_PARSE(("\nsi_parser: no table with PID %i found\n",iPid));
      uwPacketCount = 0;
      eRc = eSI_PARSER_NOT_FOUND;
      break;
    }
  } //while

#if USE_HEXDUMPS
if((_astParser[tHandle].iSectionLen > 0) && (_astParser[tHandle].iSectionComplete == 1 ))
{
  printf("***SECTION written (%i byte / %i)***\n",(int)(_astParser[tHandle].pSectionWrite - _astParser[tHandle].pSectionStart), 
         _astParser[tHandle].iSectionLen);
  hexOut(_astParser[tHandle].pSectionStart, _astParser[tHandle].iSectionLen);
  printf("***END SECTION***\n");
}
#endif

  /* store the count*/
  _astParser[tHandle].uwPacketCount = uwPacketCount;

  if (eTsRc == eTS_PARSER_INCOMPLETE)
  {
    /* need a new input buffer */
    TRACE_PARSE(("\nsi_parser: need new input buffer\n"));
    _astParser[tHandle].iSectionComplete = 0; 
    eRc = eSI_PARSER_INCOMPLETE;
  }

  if((eTsRc == eTS_PARSER_FINISHED) && ( _astParser[tHandle].iSectionComplete == 0))
  {
    TRACE_PARSE(("\nsi_parser: no (complete) table found\n"));
    eRc = eSI_PARSER_NOT_FOUND;
  }

  return eRc;
}

static void _getHeader(char* pRead,  TS_SI_TABLE_HEADER *pstParseResult)
{
  TRACE_CALLS(("_getHeader\n"));
  if ((pRead == NULL) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return;
  }
  pstParseResult->table_id                               = (*pRead) & 0xff;
  pstParseResult->section_syntax_indicator =(*(pRead + 1) >> 7) & 0x1;
  pstParseResult->private_indicator               =(*(pRead + 1) >> 6) & 0x1; 

  pstParseResult->section_length                   =((int)(*(pRead + 1) & 0x0f) << 8);       
  pstParseResult->section_length                   += *(pRead + 2) & 0xff;
}

static void _getBody(char* pRead, TU_SI_TABLE_BODY *pstParseResult)
{
  TRACE_CALLS(("_getBody\n"));
  if ((pRead == NULL) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return;
  }
  pstParseResult->st_body_long.table_id_extension = ((int)((*pRead) & 0xff)) << 8 ;
  pstParseResult->st_body_long.table_id_extension += *(pRead + 1) & 0xff; //e.g  transport stream id in PAT
  pstParseResult->st_body_long.version_number = (*(pRead + 2) >>1 ) & 0x1f;
  pstParseResult->st_body_long.current_next_indicator = *(pRead + 2) & 0x01;
  pstParseResult->st_body_long.section_number = *(pRead + 3) & 0xff;
  pstParseResult->st_body_long.last_section_number =*(pRead + 4) & 0xff;;
  pstParseResult->st_body_long.ptr_data = NULL;
 }

static TE_SI_PARSER_RC  _parserParsePAT(T_SI_PARSER_HANDLE tHandle, TS_PAT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char *pStart = NULL;
  char cOffset = 1; 
  int iProgramLoopCount = 0;
  int i;
    
  TRACE_CALLS(("_parserParsePAT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  if(_astParser[tHandle].iSectionLen >= 9 )
  {
    iProgramLoopCount = (_astParser[tHandle].iSectionLen - 5/*table body long*/ - 4/*CRC*/) / 4/*byte per program*/;

    pstResult->private_iProgramLoopLen = iProgramLoopCount;
    pstResult->pastProgram = (TS_PAT_PROGRAM*)malloc((size_t)(iProgramLoopCount * sizeof(TS_PAT_PROGRAM)));
    
    if(pstResult->pastProgram == NULL)
    {
      TRACE_ERR;
      return eSI_PARSER_ERROR;
    }
  }

  /* set up the base ptr*/
  pStart = _astParser[tHandle].pSectionBuffer;
  pRead = pStart;

  /* begin of the section -   ptr field */
  cOffset+=(*pStart) & 0xff;
  
  pRead+= cOffset;

  _getHeader(pRead,  &pstResult->stSection.stTableHeader);

  pRead+= 3;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

  /* data */
  for (i = 0; i < iProgramLoopCount; i++ )
  {
    pstResult->pastProgram[i].program_number =  ((int)((*pRead) & 0xff)) << 8 ;
    pstResult->pastProgram[i].program_number += *(pRead + 1) & 0xff;

    if(pstResult->pastProgram[i].program_number == 0)
   {
     pstResult->pastProgram[i].network_PID =  ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].network_PID += *(pRead + 3) & 0xff;
   }
   else
   {
     pstResult->pastProgram[i].program_map_PID = ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].program_map_PID += *(pRead + 3) & 0xff;
   }
   pRead+=4 /*byte per program*/;
  }

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );

  return eRc;
}

static TE_SI_PARSER_RC  _parserParsePMT(T_SI_PARSER_HANDLE tHandle, TS_PMT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char cOffset = 1; 
  int iStreamLoopLen = 0;
  int iStreamLoopCount = 0;
        
  TRACE_CALLS(("_parserParsePMT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  /* begin of the section -   ptr field */
  cOffset+= (_astParser[tHandle].pSectionBuffer[0] & 0xff);
 
  _getHeader((_astParser[tHandle].pSectionBuffer + cOffset),  &pstResult->stSection.stTableHeader);

  /* now section data begins - immmediately after section len*/
  pRead = _astParser[tHandle].pSectionStart;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

  /* data */
  pstResult->PCR_PID =  ((int) ((*pRead) & 0x1f) << 8);
  pstResult->PCR_PID += *(pRead + 1) & 0xff;

  pstResult->program_info_length =  ((int) (*(pRead + 2) & 0x0f) << 8);
  pstResult->program_info_length +=  *(pRead + 3) & 0xff;

  pRead += 4; 

  if(pstResult->program_info_length != 0)
  {
    pstResult->pDescriptorDataProgramInfo = pRead;
    
    pRead += pstResult->program_info_length;
  }
  
  if(_astParser[tHandle].iSectionLen >= (13 + pstResult->program_info_length))
  {
    iStreamLoopLen = (_astParser[tHandle].iSectionLen - 5/*table body long*/\ 
                                                                                                   - 4/*PCR_PID + program_info_length field*/\
                                                                                                   - pstResult->program_info_length\
                                                                                                   - 4/*CRC*/ ) ;

    /*allocate memory for the worst case - no descriptors at all*/
    iStreamLoopCount = (iStreamLoopLen /  5/* MIN(bytes per stream element) */);

    pstResult->pastStream = (TS_PMT_STREAM*) malloc((size_t)(iStreamLoopCount * sizeof(TS_PMT_STREAM)));

    if(pstResult->pastStream == NULL)
    {
      /* nomem */
      TRACE_ERR;
      eRc =  eSI_PARSER_ERROR;
    }
  }
  else
  {
    /*corrupt data*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }

  if(eRc == eSI_PARSER_OK)
  {
    int iByte = 0;
    int i;

    pstResult->private_iStreamLoopLen = 0; /* the caller needs to know the number of elements*/

    for(i =0; i < iStreamLoopCount; i++)
    {
      if(iByte >= (iStreamLoopLen - 5/*MIN(bytes per stream element) */))
      {
        break;
      }
     
      pstResult->pastStream[i].stream_type       = pRead[iByte++];

      pstResult->pastStream[i].elementary_PID = ((int)(pRead[iByte++] & 0x1f) << 8);
      pstResult->pastStream[i].elementary_PID += (pRead[iByte++] & 0xff);
     
      pstResult->pastStream[i].ES_info_length =  ((int)(pRead[iByte++] & 0x0f) << 8);
      pstResult->pastStream[i].ES_info_length += (pRead[iByte++] & 0xff);

      if(pstResult->pastStream[i].ES_info_length != 0)
      {
        pstResult->pastStream[i].pDescriptorDataEsInfo = &pRead[iByte];
        iByte += pstResult->pastStream[i].ES_info_length;
      }
      /* stream element*/
      pstResult->private_iStreamLoopLen++;
#if 0
      printf("  pstResult->pastStream[%i].stream_type: 0x%02x \n",i,pstResult->pastStream[i].stream_type);
      printf("  pstResult->pastStream[%i].elementary_PID: 0x%04x (%i)\n",i,pstResult->pastStream[i].elementary_PID,pstResult->pastStream[i].elementary_PID);
      printf("  pstResult->pastStream[%i].ES_info_length: 0x%04x (%i)\n",i,pstResult->pastStream[i].ES_info_length,pstResult->pastStream[i].ES_info_length);
#endif
    } //  stream loop
    
    pRead+= iStreamLoopLen;
     
    pstResult->CRC = ((*pRead)& 0xff ) << 24;
    pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
    pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
    pstResult->CRC += ((*(pRead+3))& 0xff );
  }
   
  return eRc;
}

static TE_SI_PARSER_RC  _parserParseCAT(T_SI_PARSER_HANDLE tHandle, TS_CAT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char cOffset = 1; 
    
  TRACE_CALLS(("_parserParseCAT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  /* begin of the section -   ptr field */
  cOffset+= (_astParser[tHandle].pSectionBuffer[0] & 0xff);

  _getHeader((_astParser[tHandle].pSectionBuffer + cOffset),  &pstResult->stSection.stTableHeader);

  /* now section data begins - immmediately after section len*/
  pRead = _astParser[tHandle].pSectionStart;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

  /* data */
  pstResult->pDescriptorDataCA = pRead;

  pstResult->ca_info_length = (pstResult->stSection.stTableHeader.section_length - 5/*table body*/ - 4/*CRC*/);

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );

  return eRc;
}

static TE_SI_PARSER_RC  _parserParseNIT(T_SI_PARSER_HANDLE tHandle, TS_NIT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char cOffset = 1; 
  int iStreamLoopCount = 0;
  int i;
    
  TRACE_CALLS(("_parserParseNIT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  /* begin of the section -   ptr field */
  cOffset+= (_astParser[tHandle].pSectionBuffer[0] & 0xff);
 
  _getHeader((_astParser[tHandle].pSectionBuffer + cOffset),  &pstResult->stSection.stTableHeader);

  /* now section data begins - immmediately after section len*/
  pRead = _astParser[tHandle].pSectionStart;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

  /* data */
  pstResult->network_descriptors_length = ((int) ((*pRead) & 0x0f) << 8);
  pstResult->network_descriptors_length += *(pRead + 1) & 0xff;

  pRead += 2;

  if(pstResult->network_descriptors_length != 0)
  {
    pstResult->pDescriptorDataNetwork = pRead;
    pRead += pstResult->network_descriptors_length;
  }

  pstResult->transport_stream_loop_length = ((int) ((*pRead) & 0x0f) << 8);
  pstResult->transport_stream_loop_length += *(pRead + 1) & 0xff;

  pRead += 2;

  if(pstResult->transport_stream_loop_length != 0)
  {
    /*allocate memory for the worst case - no descriptors at all*/
    iStreamLoopCount = (pstResult->transport_stream_loop_length /  6 /* MIN(bytes per transport stream element) */);

    pstResult->pastTransportStream= (TS_NIT_TRANSPORT_STREAM*) malloc((size_t)(iStreamLoopCount * sizeof(TS_NIT_TRANSPORT_STREAM)));

    if(pstResult->pastTransportStream == NULL)
    {
      /* nomem */
      TRACE_ERR;
      eRc =  eSI_PARSER_ERROR;
    }
  }

  if((eRc == eSI_PARSER_OK) && (pstResult->transport_stream_loop_length != 0))
  {
    int iByte = 0;
    
    pstResult->private_iTransportStreamLen = 0; /* the caller needs to know the number of elements*/

    for(i =0; i < pstResult->transport_stream_loop_length; i++)
    {
      if(iByte >= (pstResult->transport_stream_loop_length - 6/*MIN(bytes per stream element) */))
      {
        break;
      }

      pstResult->pastTransportStream[i].transport_stream_id = ((int)(pRead[iByte++] & 0xff) << 8);
      pstResult->pastTransportStream[i].transport_stream_id += (pRead[iByte++] & 0xff);

      pstResult->pastTransportStream[i].original_network_id = ((int)(pRead[iByte++] & 0xff) << 8);
      pstResult->pastTransportStream[i].original_network_id += (pRead[iByte++] & 0xff);

      pstResult->pastTransportStream[i].transport_descriptors_length = ((int)(pRead[iByte++] & 0x0f) << 8);
      pstResult->pastTransportStream[i].transport_descriptors_length += (pRead[iByte++] & 0xff);

      if(pstResult->pastTransportStream[i].transport_descriptors_length != 0)
      {
        pstResult->pastTransportStream[i].pDescriptorDataTransport = &pRead[iByte];
        iByte += pstResult->pastTransportStream[i].transport_descriptors_length;
      }
      /* stream element*/
      pstResult->private_iTransportStreamLen++;
    } //  stream loop
    
    pRead+= pstResult->transport_stream_loop_length;
  }   

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );
  
  return eRc;
}

static TE_SI_PARSER_RC  _parserParseBAT(T_SI_PARSER_HANDLE tHandle, TS_BAT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char cOffset = 1; 
  int iStreamLoopCount = 0;
  int i;
    
  TRACE_CALLS(("_parserParseBAT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  /* begin of the section -   ptr field */
  cOffset+= (_astParser[tHandle].pSectionBuffer[0] & 0xff);
 
  _getHeader((_astParser[tHandle].pSectionBuffer + cOffset),  &pstResult->stSection.stTableHeader);

  /* now section data begins - immmediately after section len*/
  pRead = _astParser[tHandle].pSectionStart;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

  /* data */
  pstResult->bouquet_descriptors_length = ((int) ((*pRead) & 0x0f) << 8);
  pstResult->bouquet_descriptors_length += *(pRead + 1) & 0xff;

  pRead += 2;

  if(pstResult->bouquet_descriptors_length != 0)
  {
    pstResult->pDescriptorDataBouquet = pRead;
    pRead += pstResult->bouquet_descriptors_length;
  }

  pstResult->transport_stream_loop_length = ((int) ((*pRead) & 0x0f) << 8);
  pstResult->transport_stream_loop_length += *(pRead + 1) & 0xff;

  pRead += 2;

  if(pstResult->transport_stream_loop_length != 0)
  {
    /*allocate memory for the worst case - no descriptors at all*/
    iStreamLoopCount = (pstResult->transport_stream_loop_length /  6 /* MIN(bytes per transport stream element) */);

    pstResult->pastTransportStream= (TS_BAT_TRANSPORT_STREAM*) malloc((size_t)(iStreamLoopCount * sizeof(TS_BAT_TRANSPORT_STREAM)));

    if(pstResult->pastTransportStream == NULL)
    {
      /* nomem */
      TRACE_ERR;
      eRc =  eSI_PARSER_ERROR;
    }
  }

  if((eRc == eSI_PARSER_OK) && (pstResult->transport_stream_loop_length != 0))
  {
    int iByte = 0;
    
    pstResult->private_iTransportStreamLen = 0; /* the caller needs to know the number of elements*/

    for(i =0; i < pstResult->transport_stream_loop_length; i++)
    {
      if(iByte >= (pstResult->transport_stream_loop_length - 6/*MIN(bytes per stream element) */))
      {
        break;
      }

      pstResult->pastTransportStream[i].transport_stream_id = ((int)(pRead[iByte++] & 0xff) << 8);
      pstResult->pastTransportStream[i].transport_stream_id += (pRead[iByte++] & 0xff);

      pstResult->pastTransportStream[i].original_network_id = ((int)(pRead[iByte++] & 0xff) << 8);
      pstResult->pastTransportStream[i].original_network_id += (pRead[iByte++] & 0xff);

      pstResult->pastTransportStream[i].transport_descriptors_length = ((int)(pRead[iByte++] & 0x0f) << 8);
      pstResult->pastTransportStream[i].transport_descriptors_length += (pRead[iByte++] & 0xff);

      if(pstResult->pastTransportStream[i].transport_descriptors_length != 0)
      {
        pstResult->pastTransportStream[i].pDescriptorDataTransport = &pRead[iByte];
        iByte += pstResult->pastTransportStream[i].transport_descriptors_length;
      }
      /* stream element*/
      pstResult->private_iTransportStreamLen++;
    } //  stream loop
    
    pRead+= pstResult->transport_stream_loop_length;
  }   

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );
  
  return eRc;
}

static TE_SI_PARSER_RC  _parserParseSDT(T_SI_PARSER_HANDLE tHandle, TS_SDT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char cOffset = 1; 
  int iServiceLoopCount = 0;
  int iServiceLoopLen = 0;
  int i;
    
  TRACE_CALLS(("_parserParseSDT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  /* begin of the section -   ptr field */
  cOffset+= (_astParser[tHandle].pSectionBuffer[0] & 0xff);
 
  _getHeader((_astParser[tHandle].pSectionBuffer + cOffset),  &pstResult->stSection.stTableHeader);

  /* now section data begins - immmediately after section len*/
  pRead = _astParser[tHandle].pSectionStart;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

  /* data */
  pstResult->original_network_id = ((int) ((*pRead) & 0xff) << 8);
  pstResult->original_network_id += *(pRead + 1) & 0xff;

  pRead += 3; //skip reserved byte


  if(_astParser[tHandle].iSectionLen >= 12)
  {
    iServiceLoopLen = (_astParser[tHandle].iSectionLen - 5/*table body long*/\ 
                                                                                                   - 2/*original_network_id*/\
                                                                                                   - 1/*reserved*/\
                                                                                                   - 4/*CRC*/ ) ;

    /*allocate memory for the worst case - no descriptors at all*/
    iServiceLoopCount = (iServiceLoopLen /  5/* MIN(bytes per stream element) */);

    pstResult->pastService = (TS_SDT_SERVICE*) malloc((size_t)(iServiceLoopCount * sizeof(TS_SDT_SERVICE)));

    if(pstResult->pastService == NULL)
    {
      /* nomem */
      TRACE_ERR;
      eRc =  eSI_PARSER_ERROR;
    }
  }
  else
  {
    /*corrupt data*/
    TRACE_ERR;
    eRc = eSI_PARSER_ERROR;
  }

  if((eRc == eSI_PARSER_OK) && (iServiceLoopLen != 0))
  {
    int iByte = 0;
    
    pstResult->private_iServiceLen = 0; /* the caller needs to know the number of elements*/

    for(i =0; i < iServiceLoopLen; i++)
    {
      if(iByte >= (iServiceLoopLen - 5/*MIN(bytes per stream element) */))
      {
        break;
      }

      pstResult->pastService[i].service_id = ((int)(pRead[iByte++] & 0xff) << 8);
      pstResult->pastService[i].service_id += (pRead[iByte++] & 0xff);

      pstResult->pastService[i].EIT_schedule_flag = ((pRead[iByte]) >> 1) & 0x1; //stay on this byte
      pstResult->pastService[i].EIT_present_following_flag =(pRead[iByte++]) & 0x01;

      pstResult->pastService[i].running_status = ((pRead[iByte]) >> 5) & 0x7; //stay on this byte
      pstResult->pastService[i].free_CA_mode = ((pRead[iByte]) >> 4) & 0x1; //stay on this byte

      pstResult->pastService[i].descriptors_loop_length = ((int)(pRead[iByte++] & 0x0f) << 8);
      pstResult->pastService[i].descriptors_loop_length += (pRead[iByte++] & 0xff);

      if( pstResult->pastService[i].descriptors_loop_length != 0)
      {
        pstResult->pastService[i].pDescriptorDataService = &pRead[iByte];
        iByte += pstResult->pastService[i].descriptors_loop_length;
      }
      /* stream element*/
      pstResult->private_iServiceLen++;
    } //  stream loop
    
    pRead+= iServiceLoopLen;
  }   

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );
  
  return eRc;
}

static TE_SI_PARSER_RC  _parserParseEIT(T_SI_PARSER_HANDLE tHandle, TS_EIT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char *pStart = NULL;
  char cOffset = 1; 
  int iProgramLoopCount = 0;
  int i;
    
  TRACE_CALLS(("_parserParseEIT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  //to adapt  forpmt!!
#if 0
  if(_astParser[tHandle].iSectionLen >= 9 )
  {
    iProgramLoopCount = (_astParser[tHandle].iSectionLen - 5/*table body long*/ - 4/*CRC*/) / 4/*byte per program*/;

    pstResult->iProgramLoopLen = iProgramLoopCount;
    pstResult->pastProgram = (TS_PAT_PROGRAM*)malloc((size_t)(iProgramLoopCount * sizeof(TS_PAT_PROGRAM)));
    
    if(pstResult->pastProgram == NULL)
    {
      TRACE_ERR;
      return eSI_PARSER_ERROR;
    }
  }
#endif
  /* set up the base ptr*/
  pStart = _astParser[tHandle].pSectionBuffer;
  pRead = pStart;

  /* begin of the section -   ptr field */
  cOffset+=(*pStart) & 0xff;
  
  pRead+= cOffset;

  _getHeader(pRead,  &pstResult->stSection.stTableHeader);

  pRead+= 3;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

#if 0
  /* data */
  for (i = 0; i < iProgramLoopCount; i++ )
  {
    pstResult->pastProgram[i].program_number =  ((int)((*pRead) & 0xff)) << 8 ;
    pstResult->pastProgram[i].program_number += *(pRead + 1) & 0xff;

    if(pstResult->pastProgram[i].program_number == 0)
   {
     pstResult->pastProgram[i].network_PID =  ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].network_PID += *(pRead + 3) & 0xff;
   }
   else
   {
     pstResult->pastProgram[i].program_map_PID = ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].program_map_PID += *(pRead + 3) & 0xff;
   }
   pRead+=4 /*byte per program*/;
  }

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );
#endif
  return eRc;
}

static TE_SI_PARSER_RC  _parserParseRST(T_SI_PARSER_HANDLE tHandle, TS_RST *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char *pStart = NULL;
  char cOffset = 1; 
  int iProgramLoopCount = 0;
  int i;
    
  TRACE_CALLS(("_parserParseRST\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  //to adapt  forpmt!!
#if 0
  if(_astParser[tHandle].iSectionLen >= 9 )
  {
    iProgramLoopCount = (_astParser[tHandle].iSectionLen - 5/*table body long*/ - 4/*CRC*/) / 4/*byte per program*/;

    pstResult->iProgramLoopLen = iProgramLoopCount;
    pstResult->pastProgram = (TS_PAT_PROGRAM*)malloc((size_t)(iProgramLoopCount * sizeof(TS_PAT_PROGRAM)));
    
    if(pstResult->pastProgram == NULL)
    {
      TRACE_ERR;
      return eSI_PARSER_ERROR;
    }
  }
#endif
  /* set up the base ptr*/
  pStart = _astParser[tHandle].pSectionBuffer;
  pRead = pStart;

  /* begin of the section -   ptr field */
  cOffset+=(*pStart) & 0xff;
  
  pRead+= cOffset;

  _getHeader(pRead,  &pstResult->stSection.stTableHeader);

  pRead+= 3;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

#if 0
  /* data */
  for (i = 0; i < iProgramLoopCount; i++ )
  {
    pstResult->pastProgram[i].program_number =  ((int)((*pRead) & 0xff)) << 8 ;
    pstResult->pastProgram[i].program_number += *(pRead + 1) & 0xff;

    if(pstResult->pastProgram[i].program_number == 0)
   {
     pstResult->pastProgram[i].network_PID =  ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].network_PID += *(pRead + 3) & 0xff;
   }
   else
   {
     pstResult->pastProgram[i].program_map_PID = ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].program_map_PID += *(pRead + 3) & 0xff;
   }
   pRead+=4 /*byte per program*/;
  }

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );
#endif
  return eRc;
}

static TE_SI_PARSER_RC  _parserParseTDT(T_SI_PARSER_HANDLE tHandle, TS_TDT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char *pStart = NULL;
  char cOffset = 1; 
  int iProgramLoopCount = 0;
  int i;
    
  TRACE_CALLS(("_parserParseTDT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  //to adapt  forpmt!!
#if 0
  if(_astParser[tHandle].iSectionLen >= 9 )
  {
    iProgramLoopCount = (_astParser[tHandle].iSectionLen - 5/*table body long*/ - 4/*CRC*/) / 4/*byte per program*/;

    pstResult->iProgramLoopLen = iProgramLoopCount;
    pstResult->pastProgram = (TS_PAT_PROGRAM*)malloc((size_t)(iProgramLoopCount * sizeof(TS_PAT_PROGRAM)));
    
    if(pstResult->pastProgram == NULL)
    {
      TRACE_ERR;
      return eSI_PARSER_ERROR;
    }
  }
#endif
  /* set up the base ptr*/
  pStart = _astParser[tHandle].pSectionBuffer;
  pRead = pStart;

  /* begin of the section -   ptr field */
  cOffset+=(*pStart) & 0xff;
  
  pRead+= cOffset;

  _getHeader(pRead,  &pstResult->stSection.stTableHeader);

  pRead+= 3;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

#if 0
  /* data */
  for (i = 0; i < iProgramLoopCount; i++ )
  {
    pstResult->pastProgram[i].program_number =  ((int)((*pRead) & 0xff)) << 8 ;
    pstResult->pastProgram[i].program_number += *(pRead + 1) & 0xff;

    if(pstResult->pastProgram[i].program_number == 0)
   {
     pstResult->pastProgram[i].network_PID =  ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].network_PID += *(pRead + 3) & 0xff;
   }
   else
   {
     pstResult->pastProgram[i].program_map_PID = ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].program_map_PID += *(pRead + 3) & 0xff;
   }
   pRead+=4 /*byte per program*/;
  }

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );
#endif
  return eRc;
}

static TE_SI_PARSER_RC  _parserParseTOT(T_SI_PARSER_HANDLE tHandle, TS_TOT *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char *pStart = NULL;
  char cOffset = 1; 
  int iProgramLoopCount = 0;
  int i;
    
  TRACE_CALLS(("_parserParseTOT\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  //to adapt  forpmt!!
#if 0
  if(_astParser[tHandle].iSectionLen >= 9 )
  {
    iProgramLoopCount = (_astParser[tHandle].iSectionLen - 5/*table body long*/ - 4/*CRC*/) / 4/*byte per program*/;

    pstResult->iProgramLoopLen = iProgramLoopCount;
    pstResult->pastProgram = (TS_PAT_PROGRAM*)malloc((size_t)(iProgramLoopCount * sizeof(TS_PAT_PROGRAM)));
    
    if(pstResult->pastProgram == NULL)
    {
      TRACE_ERR;
      return eSI_PARSER_ERROR;
    }
  }
#endif
  /* set up the base ptr*/
  pStart = _astParser[tHandle].pSectionBuffer;
  pRead = pStart;

  /* begin of the section -   ptr field */
  cOffset+=(*pStart) & 0xff;
  
  pRead+= cOffset;

  _getHeader(pRead,  &pstResult->stSection.stTableHeader);

  pRead+= 3;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

#if 0
  /* data */
  for (i = 0; i < iProgramLoopCount; i++ )
  {
    pstResult->pastProgram[i].program_number =  ((int)((*pRead) & 0xff)) << 8 ;
    pstResult->pastProgram[i].program_number += *(pRead + 1) & 0xff;

    if(pstResult->pastProgram[i].program_number == 0)
   {
     pstResult->pastProgram[i].network_PID =  ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].network_PID += *(pRead + 3) & 0xff;
   }
   else
   {
     pstResult->pastProgram[i].program_map_PID = ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].program_map_PID += *(pRead + 3) & 0xff;
   }
   pRead+=4 /*byte per program*/;
  }

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );
#endif
  return eRc;
}

static TE_SI_PARSER_RC  _parserParseST(T_SI_PARSER_HANDLE tHandle, TS_ST *pstResult)
{
  TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
  char *pRead = NULL;
  char *pStart = NULL;
  char cOffset = 1; 
  int iProgramLoopCount = 0;
  int i;
    
  TRACE_CALLS(("_parserParseST\n"));

  if((tHandle >= MAX_SI_PARSER) || (pstResult == NULL) || (_astParser[tHandle].pSectionBuffer == NULL))
  {
    TRACE_ERR;
    return eSI_PARSER_ERROR;
  }

  //to adapt  forpmt!!
#if 0
  if(_astParser[tHandle].iSectionLen >= 9 )
  {
    iProgramLoopCount = (_astParser[tHandle].iSectionLen - 5/*table body long*/ - 4/*CRC*/) / 4/*byte per program*/;

    pstResult->iProgramLoopLen = iProgramLoopCount;
    pstResult->pastProgram = (TS_PAT_PROGRAM*)malloc((size_t)(iProgramLoopCount * sizeof(TS_PAT_PROGRAM)));
    
    if(pstResult->pastProgram == NULL)
    {
      TRACE_ERR;
      return eSI_PARSER_ERROR;
    }
  }
#endif
  /* set up the base ptr*/
  pStart = _astParser[tHandle].pSectionBuffer;
  pRead = pStart;

  /* begin of the section -   ptr field */
  cOffset+=(*pStart) & 0xff;
  
  pRead+= cOffset;

  _getHeader(pRead,  &pstResult->stSection.stTableHeader);

  pRead+= 3;

  _getBody(pRead, &pstResult->stSection.stTableBody);

  pRead += 5;

#if 0
  /* data */
  for (i = 0; i < iProgramLoopCount; i++ )
  {
    pstResult->pastProgram[i].program_number =  ((int)((*pRead) & 0xff)) << 8 ;
    pstResult->pastProgram[i].program_number += *(pRead + 1) & 0xff;

    if(pstResult->pastProgram[i].program_number == 0)
   {
     pstResult->pastProgram[i].network_PID =  ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].network_PID += *(pRead + 3) & 0xff;
   }
   else
   {
     pstResult->pastProgram[i].program_map_PID = ((int) (*(pRead + 2) & 0x1f) << 8);
     pstResult->pastProgram[i].program_map_PID += *(pRead + 3) & 0xff;
   }
   pRead+=4 /*byte per program*/;
  }

  pstResult->CRC = ((*pRead)& 0xff ) << 24;
  pstResult->CRC += ((*(pRead+1))& 0xff ) << 16;
  pstResult->CRC += ((*(pRead+2))& 0xff ) << 8;
  pstResult->CRC += ((*(pRead+3))& 0xff );
#endif
  return eRc;
}

