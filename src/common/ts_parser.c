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

#include "pubh/ts_parser.h"

#define TRACE_IF(x)          //printf x         
#define TRACE_CALLS(x) //printf x
#define TRACE_PARSE(x) //printf x

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

#define MAX_TS_PARSER (10)


static pthread_mutex_t  _tMutexParserTable = PTHREAD_MUTEX_INITIALIZER;

#define LOCK_PARSER_TABLE {if(pthread_mutex_lock(&_tMutexParserTable)) {TRACE_ERR;}}
#define UNLOCK_PARSER_TABLE {if(pthread_mutex_unlock(&_tMutexParserTable)) {TRACE_ERR;}}


typedef enum
{
  ePARSER_IDLE,
  ePARSER_PARSING,
  ePARSER_INCOMPLETE
} TE_PARSER_STATE;

typedef struct
{
  unsigned long uwCallerContext;
  TE_PARSER_STATE eState;
  unsigned long uwByteOffset;
  char abInComplete[TS_PACKET_SIZE];
  int  iIncompleteOffset; 

} TS_PARSER;

static TS_PARSER _astParser[MAX_TS_PARSER];

static int _bIsFirstCreation = 1;

/*
** private 
*/
static void _initParserData(void);
static TE_TS_PARSER_RC _eGetFreeHandle(T_TS_PARSER_HANDLE *pHandle);
static TE_TS_PARSER_RC _parserParse(T_TS_PARSER_HANDLE tHandle,
                                    char* pabStart, 
                                    unsigned long  uwLen, 
                                    TS_PACKET_DATA *pstParseResult, 
                                    unsigned long *puwRead);
static void _getHeader(char* pRead,  TS_PACKET_DATA *pstParseResult);
static void _getAdaptationField(char* pRead,  TS_PACKET_DATA *pstParseResult);

static TE_TS_PARSER_RC _handleIdle(T_TS_PARSER_HANDLE tHandle, 
                                   char* pabInputBuffer, 
                                   unsigned long uwBufferLen,  
                                   TS_PACKET_DATA *pstParseResult);

static TE_TS_PARSER_RC _handleParsing(T_TS_PARSER_HANDLE tHandle, 
                                      char* pabInputBuffer, 
                                      unsigned long uwBufferLen,  
                                      TS_PACKET_DATA *pstParseResult);

static TE_TS_PARSER_RC _handleIncomplete(T_TS_PARSER_HANDLE tHandle, 
                                         char* pabInputBuffer, 
                                         unsigned long uwBufferLen,  
                                         TS_PACKET_DATA *pstParseResult);


/*
** API
*/
TE_TS_PARSER_RC  ts_parser_e_create(T_TS_PARSER_HANDLE  *pHandle)
{
  TE_TS_PARSER_RC eRc = eTS_PARSER_OK;

  TRACE_IF(("ts_parser_e_create\n"));

  if (pHandle == NULL)
  {
    TRACE_ERR;
    return eTS_PARSER_ERROR;
  }

  if (_bIsFirstCreation == 1)
  {
    LOCK_PARSER_TABLE;

    _initParserData();
    _bIsFirstCreation = 0;

    UNLOCK_PARSER_TABLE;
  }

  LOCK_PARSER_TABLE;

  if (_eGetFreeHandle(pHandle))
  {
    TRACE_ERR;
    eRc = eTS_PARSER_ERROR;
  }
  else
  {
    _astParser[*pHandle].uwCallerContext = 17; // (unsigned long)pthread_self(); DOESNT'WORK
    _astParser[*pHandle].eState                  = ePARSER_IDLE;
    _astParser[*pHandle].uwByteOffset     = 0;
    memset(_astParser[*pHandle].abInComplete, 0, TS_PACKET_SIZE);
    _astParser[*pHandle].iIncompleteOffset  = 0;

  }

  UNLOCK_PARSER_TABLE;

  return eRc;
}

TE_TS_PARSER_RC  ts_parser_e_destroy(T_TS_PARSER_HANDLE  tHandle)
{
  TE_TS_PARSER_RC eRc = eTS_PARSER_OK;

  TRACE_IF(("ts_parser_e_destroy\n"));

  if (tHandle >= MAX_TS_PARSER)
  {
    TRACE_ERR;
    return eTS_PARSER_ERROR;
  }

  LOCK_PARSER_TABLE;

  _astParser[tHandle].uwCallerContext = (unsigned long)NULL;
  _astParser[tHandle].eState                   = ePARSER_IDLE;
  _astParser[tHandle].uwByteOffset      = 0;
  memset(_astParser[tHandle].abInComplete, 0, TS_PACKET_SIZE);
  _astParser[tHandle].iIncompleteOffset  = 0;

  UNLOCK_PARSER_TABLE;

  return eRc;
}

TE_TS_PARSER_RC  ts_parser_e_parse(T_TS_PARSER_HANDLE  tHandle, 
                                   char* pabInputBuffer, 
                                   unsigned long uwBufferLen,  
                                   int iReset,
                                   TS_PACKET_DATA *pstParseResult )
{
  TE_TS_PARSER_RC eRc = eTS_PARSER_OK;

  TRACE_IF(("ts_parser_e_parse\n"));

  if ((tHandle >= MAX_TS_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eTS_PARSER_ERROR;
  }

  memset(pstParseResult, 0, sizeof(TS_PACKET_DATA));

  if (_astParser[tHandle].uwCallerContext == 0 )
  {
    /* parser not valid anymore*/
    TRACE_ERR;
    eRc = eTS_PARSER_ERROR;
  }
  else
  {
    TE_PARSER_STATE eNewState = _astParser[tHandle].eState; // init value

    if (iReset == 1)
    {
      /* clear all read ptrs and start fresh with given buffer*/
      _astParser[tHandle].eState                      = ePARSER_IDLE;
      _astParser[tHandle].uwByteOffset          = 0;
      memset(_astParser[tHandle].abInComplete, 0, TS_PACKET_SIZE);
      _astParser[tHandle].iIncompleteOffset  = 0;
    }

    switch (_astParser[tHandle].eState)
    {
    case ePARSER_IDLE:
      {
        eRc = _handleIdle(tHandle, pabInputBuffer, uwBufferLen,  pstParseResult);
      }
      break;
    case ePARSER_PARSING:
      {
        eRc = _handleParsing(tHandle, pabInputBuffer, uwBufferLen,  pstParseResult);
      }
      break;
    case ePARSER_INCOMPLETE:
      {
        eRc = _handleIncomplete(tHandle, pabInputBuffer, uwBufferLen,  pstParseResult);
      }
      break;
    default:TRACE_ERR; break;
    }

    switch (eRc)
    {
    case eTS_PARSER_OK:                   eNewState = ePARSER_PARSING; break;
    case eTS_PARSER_INCOMPLETE: eNewState = ePARSER_INCOMPLETE; break;
    case eTS_PARSER_FINISHED:       eNewState = ePARSER_IDLE; break;

    default:TRACE_ERR; break;
    }

    /* store the state*/
    _astParser[tHandle].eState = eNewState;
  }

  return eRc;
}


/*
** private impl.
*/

static TE_TS_PARSER_RC _handleIdle(T_TS_PARSER_HANDLE tHandle, 
                                   char* pabInputBuffer, 
                                   unsigned long uwBufferLen,  
                                   TS_PACKET_DATA *pstParseResult)
{
  TE_TS_PARSER_RC eRc = eTS_PARSER_OK;

  unsigned long uwRead = 0;
  unsigned long uwLen = 0;
  char* pabStart  = NULL;

  TRACE_CALLS(("_handleIdle\n"));

  if ((tHandle >= MAX_TS_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eTS_PARSER_ERROR;
  }

  /* fresh start */
  pabStart = pabInputBuffer;
  uwLen    = uwBufferLen;

  eRc = _parserParse(tHandle, pabStart, uwLen, pstParseResult, &uwRead);

  if (eRc == eTS_PARSER_INCOMPLETE)
  {
    _astParser[tHandle].uwByteOffset = 0;
  }
  else if (eRc == eTS_PARSER_OK)
  {
    _astParser[tHandle].uwByteOffset += uwRead;

    if (_astParser[tHandle].uwByteOffset == uwBufferLen)
    {
      /*we read the whole buf */
      _astParser[tHandle].uwByteOffset = 0;
      eRc = eTS_PARSER_FINISHED;
    }
  }
  else
  {
    TRACE_ERR;
  }

  return eRc;
}

static TE_TS_PARSER_RC _handleIncomplete(T_TS_PARSER_HANDLE tHandle, 
                                         char* pabInputBuffer, 
                                         unsigned long uwBufferLen,  
                                         TS_PACKET_DATA *pstParseResult)
{
  TRACE_CALLS(("_handleIncomplete\n"));
  return _handleIdle(tHandle, pabInputBuffer, uwBufferLen, pstParseResult);
}

static TE_TS_PARSER_RC _handleParsing(T_TS_PARSER_HANDLE tHandle, 
                                      char* pabInputBuffer, 
                                      unsigned long uwBufferLen,  
                                      TS_PACKET_DATA *pstParseResult)
{
  TE_TS_PARSER_RC eRc = eTS_PARSER_OK;

  unsigned long uwRead = 0;
  unsigned long uwLen = 0;
  char* pabStart  = NULL;

  TRACE_CALLS(("_handleParsing\n"));

  if ((tHandle >= MAX_TS_PARSER) || (pabInputBuffer == NULL) || (uwBufferLen == 0) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return eTS_PARSER_ERROR;
  }

  /*buffer in progress*/
  pabStart = pabInputBuffer +  _astParser[tHandle].uwByteOffset;
  uwLen    = uwBufferLen - _astParser[tHandle].uwByteOffset;

  eRc = _parserParse(tHandle, pabStart, uwLen, pstParseResult, &uwRead);

  if (eRc == eTS_PARSER_INCOMPLETE)
  {
    _astParser[tHandle].uwByteOffset = 0;
  }
  else if (eRc == eTS_PARSER_OK)
  {
    _astParser[tHandle].uwByteOffset += uwRead;

    if (_astParser[tHandle].uwByteOffset == uwBufferLen)
    {
      /*we read the whole buf */
      _astParser[tHandle].uwByteOffset = 0;
      eRc = eTS_PARSER_FINISHED;
    }
  }
  else
  {
    TRACE_ERR;
  }

  return eRc;
}

static void _initParserData(void)
{
  TRACE_CALLS(("_initParserData\n"));

  memset(_astParser, 0,  sizeof(TS_PARSER) * MAX_TS_PARSER );
}

static TE_TS_PARSER_RC _eGetFreeHandle(T_TS_PARSER_HANDLE *pHandle)
{
  TE_TS_PARSER_RC eRc = eTS_PARSER_ERROR;
  int i;

  TRACE_CALLS(("_eGetFreeHandle\n"));

  if (pHandle == NULL)
  {
    TRACE_ERR;
    return eRc;
  }

  *pHandle = TS_PARSER_INVALID;

  for (i = 0; i < MAX_TS_PARSER; i++)
  {
    if (_astParser[i].uwCallerContext == 0 )
    {
      *pHandle = (T_TS_PARSER_HANDLE)i;
      eRc = eTS_PARSER_OK;
      break;
    }
  }

  return eRc;
}

static TE_TS_PARSER_RC _parserParse(T_TS_PARSER_HANDLE tHandle,
                                    char* pabStart, 
                                    unsigned long  uwLen, 
                                    TS_PACKET_DATA *pstParseResult, 
                                    unsigned long *puwRead)
{
  TE_TS_PARSER_RC eRc = eTS_PARSER_OK;
  char* pRead = NULL;
  char* pStart = NULL;
  int sync = 0;
  unsigned long uwByteRead = 0;

  TRACE_CALLS(("_parserParse\n"));

  if (( tHandle >= MAX_TS_PARSER ) || (pabStart == NULL) || (uwLen == 0) || (pstParseResult == NULL) || (puwRead == NULL))
  {
    TRACE_ERR;
    return eTS_PARSER_ERROR;
  }

  /* set up local ptr*/
  pStart  = pabStart;
  pRead = pStart;

  if (_astParser[tHandle].iIncompleteOffset != 0)
  {
    /* we have to assume a sync to the last partial packet*/
    sync = 1;
  }
  else
  {
    sync = (*pStart == 0x47);
  }

  if ( !sync )
  {
    TRACE_PARSE(("!!out of sync!! try to sync\n"));

    /*check the len first*/
    if (uwLen < 4 * TS_PACKET_SIZE)
    {
      /* to less data to get a sync*/
      TRACE_ERR;
      return eTS_PARSER_ERROR;
    }

    /* get the SYNC - we need at least 3 packets - standard says 5 but anyway */
    while (((pRead + 3 * TS_PACKET_SIZE) - pabStart)  <= uwLen)
    {
      if ( (*pRead                    == 0x47)  &&  
           (*(pRead + TS_PACKET_SIZE)       == 0x47)  && 
           (*(pRead + 2* TS_PACKET_SIZE)  == 0x47))
      {
        sync = 1;
        break;
      }
      pRead++;
    }
  }

  if (sync)
  {
    /* handle incomplete packets from given buffer*/
    if (uwLen < TS_PACKET_SIZE)
    {
      /* get all we can get */
      memcpy(_astParser[tHandle].abInComplete, pabStart, (size_t)uwLen);

      _astParser[tHandle].iIncompleteOffset = (int)uwLen;

      *puwRead = uwLen;

      return eTS_PARSER_INCOMPLETE;
    }

    /* get the complete ts packet*/
    if ( _astParser[tHandle].iIncompleteOffset != 0)
    {
      memcpy(&_astParser[tHandle].abInComplete[_astParser[tHandle].iIncompleteOffset],  pabStart, (TS_PACKET_SIZE -  _astParser[tHandle].iIncompleteOffset) );

      pStart        = _astParser[tHandle].abInComplete;
      pRead       = pStart ;
    }
    else
    {
      /* reinit */
      memset(_astParser[tHandle].abInComplete, 0, TS_PACKET_SIZE);
    }

    TRACE_PARSE(("found ts sync 0x%x\n",(*pRead) & 0xff));

    TRACE_PARSE(("header: "));
    TRACE_PARSE(("["BYTETOBINARYPATTERN"]", BYTETOBINARY(*pRead)));
    TRACE_PARSE(("["BYTETOBINARYPATTERN"]", BYTETOBINARY(*(pRead+1))));
    TRACE_PARSE(("["BYTETOBINARYPATTERN"]", BYTETOBINARY(*(pRead+2))));
    TRACE_PARSE(("["BYTETOBINARYPATTERN"]\n", BYTETOBINARY(*(pRead+3))));

    /* first byte after sync word */
    pRead++;

    _getHeader(pRead, pstParseResult);

    /* payload / adaptation field start*/
    pRead+=3;

    if ((pstParseResult->stHeader.adaption_field_control == 0x2) || 
        (pstParseResult->stHeader.adaption_field_control == 0x3))
    {
      /* adaptation field present */ 
      pstParseResult->iValidAdaptation = 1;

      _getAdaptationField(pRead, pstParseResult);

      /* payload */
      pRead += pstParseResult->stAdaptation.adaptation_field_len;
    }

    pstParseResult->pabPayload  = pRead;
    pstParseResult->iPayloadLen = (TS_PACKET_SIZE - 4 - pstParseResult->stAdaptation.adaptation_field_len);

    uwByteRead = ((pRead - pStart) + pstParseResult->iPayloadLen) - _astParser[tHandle].iIncompleteOffset;

    if (_astParser[tHandle].iIncompleteOffset != 0)
    {
      _astParser[tHandle].iIncompleteOffset = 0;
    }
  }
  else
  {
    TRACE_PARSE(("no ts sync found\n"));
    eRc = eTS_PARSER_ERROR; 
  }

  /* return packet data */
  *puwRead = uwByteRead;

  return eRc;
}

static void _getAdaptationField(char* pRead,  TS_PACKET_DATA *pstParseResult)
{
  char *pTmp = NULL;

  if ((pRead == NULL) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return;
  }

  /* adaptation field start*/
  pTmp = pRead;

  pstParseResult->stAdaptation.adaptation_field_len                          =  *pTmp & 0xff;
  pstParseResult->stAdaptation.discontinuity_indicator                      = (*(pTmp+1) >> 7) & 0x1;
  pstParseResult->stAdaptation.random_access_indicator                 = (*(pTmp+1) >> 6) & 0x1;
  pstParseResult->stAdaptation.elemtary_stream_priority_indicator = (*(pTmp+1) >> 5) & 0x1;
  pstParseResult->stAdaptation.PCR_flag                                                = (*(pTmp+1) >> 4) & 0x1;
  pstParseResult->stAdaptation.OPCR_flag                                             = (*(pTmp+1) >> 3) & 0x1;
  pstParseResult->stAdaptation.splicing_point_flag                             = (*(pTmp+1) >> 2) & 0x1;
  pstParseResult->stAdaptation.transport_private_data_flag             = (*(pTmp+1) >> 1) & 0x1;
  pstParseResult->stAdaptation.adaptation_field_extension_flag     = *(pTmp+1)  & 0x1;

  /* adaptation field data */
  pTmp+=2;

  if (pstParseResult->stAdaptation.PCR_flag == 1)
  {
    pstParseResult->stAdaptation.program_clock_reference_base =     (((long int)((*pTmp) & 0xff) ) << 32); //MSB
    pstParseResult->stAdaptation.program_clock_reference_base +=  (((long int)((*pTmp+1) & 0xff)) << 24);
    pstParseResult->stAdaptation.program_clock_reference_base +=  (((long int)((*pTmp+2) & 0xff)) << 16);
    pstParseResult->stAdaptation.program_clock_reference_base +=  (((long int)((*pTmp+3) & 0xff)) << 8);
    pstParseResult->stAdaptation.program_clock_reference_base +=  ((*pTmp+4) >> 7) & 0x1;     //LSB

    pstParseResult->stAdaptation.program_clock_reference_extension =    ((*(pTmp+4) & 0x1) << 8);
    pstParseResult->stAdaptation.program_clock_reference_extension += *(pTmp+5)& 0xff;

    /* goto OPCR data or following one*/
    pTmp += 6;
  }

  if (pstParseResult->stAdaptation.OPCR_flag == 1)
  {
    pstParseResult->stAdaptation.original_program_clock_reference_base =     (((long int)(*pTmp)) << 32); //MSB
    pstParseResult->stAdaptation.original_program_clock_reference_base +=  (((long int)(*pTmp+1)) << 24);
    pstParseResult->stAdaptation.original_program_clock_reference_base +=  (((long int)(*pTmp+2)) << 16);
    pstParseResult->stAdaptation.original_program_clock_reference_base +=  (((long int)(*pTmp+3)) << 8);
    pstParseResult->stAdaptation.original_program_clock_reference_base +=  ((*pTmp+4) >> 7) & 0x1;     //LSB

    pstParseResult->stAdaptation.original_program_clock_reference_base =    ((*(pTmp+4) & 0x1) << 8);
    pstParseResult->stAdaptation.original_program_clock_reference_base += *(pTmp+5);

    /* goto splicing point data or following one */
    pTmp += 6;
  }

  if (pstParseResult->stAdaptation.splicing_point_flag == 1)
  {
    pstParseResult->stAdaptation.splice_countdown = *pTmp;

    /* goto transport private data or following one */
    pTmp += 1 ;
  }

  if (pstParseResult->stAdaptation.transport_private_data_flag == 1)
  {
    pstParseResult->stAdaptation.transport_private_data_length = *pTmp;
    pstParseResult->stAdaptation.ptr_transport_private_data = (pTmp+1);

    /* goto adaptation_field_extension data or following one */
    pTmp += (1 + pstParseResult->stAdaptation.transport_private_data_length);
  }

  if (pstParseResult->stAdaptation.adaptation_field_extension_flag == 1)
  {
    pstParseResult->stAdaptation.adaptation_field_extension_len =    *pTmp & 0xff;
    pstParseResult->stAdaptation.ltw_flag                                           =  (*(pTmp+1) >> 7) & 0x1;
    pstParseResult->stAdaptation.piecewise_rate_flag                     =  (*(pTmp+1) >> 6) & 0x1;
    pstParseResult->stAdaptation.seamless_splice_flag                   =  (*(pTmp+1) >> 5) & 0x1;

    /*  next data sub element  -  ltw and/or piecewise and/or seamless data */
    pTmp += 2;

    if (pstParseResult->stAdaptation.ltw_flag == 1)
    {
      pstParseResult->stAdaptation.ltw_valid_flag =              (*pTmp >> 7) & 0x1; 
      pstParseResult->stAdaptation.ltw_offset       =     ((int)((*pTmp) & 0x7f)  << 8) ;
      pstParseResult->stAdaptation.ltw_offset       +=            *(pTmp+1);

      /* goto piecewise data or following*/
      pTmp += 2;
    }

    if (pstParseResult->stAdaptation.piecewise_rate_flag == 1)
    {
      pstParseResult->stAdaptation.piecewise_rate = ((int)((*pTmp) & 0x3f) << 8);
      pstParseResult->stAdaptation.piecewise_rate += *(pTmp+1);

      /*  goto seamless  data or end */
      pTmp += 3;
    }

    if (pstParseResult->stAdaptation.seamless_splice_flag == 1)
    {
      pstParseResult->stAdaptation.splice_type    =    ((*pTmp) & 0xf0) >> 4;
      /* WTF !!!? marker bits? !! argghh !!*/
      TRACE_ERR; //should be checked with test packet
      pstParseResult->stAdaptation.DTS_next_AU = (((long int) (((*pTmp) & 0xe) >> 1))  << 30);
      pstParseResult->stAdaptation.DTS_next_AU += ((long int) (*(pTmp+1)) << 22);
      pstParseResult->stAdaptation.DTS_next_AU += (((long int) ((*(pTmp+2) & 0xfe) >> 1)) << 15);
      pstParseResult->stAdaptation.DTS_next_AU += ((long int) (*(pTmp+3)) << 6);
      pstParseResult->stAdaptation.DTS_next_AU += ((long int) (*(pTmp+4)) << 7);
    }
  } //extension field
}

static void _getHeader(char* pRead,  TS_PACKET_DATA *pstParseResult)
{
  if ((pRead == NULL) || (pstParseResult == NULL))
  {
    TRACE_ERR;
    return;
  }
  pstParseResult->stHeader.transport_error_indicator         =  (*pRead >> 7) & 0x1;
  pstParseResult->stHeader.payload_unit_start_indicator   =  (*pRead >> 6) & 0x1;
  pstParseResult->stHeader.transport_priority                       =  (*pRead >> 5) & 0x1;
  pstParseResult->stHeader.PID                                                =  ((int) ( (*pRead) & 0x1F) << 8) + (*(pRead+1) & 0xff ) ;
  pstParseResult->stHeader.transport_scrambling_control =  (*(pRead+2) >> 6) & 0x3;
  pstParseResult->stHeader.adaption_field_control             =  (*(pRead+2) >> 4) & 0x3; 
  pstParseResult->stHeader.continuity_counter                   =  *(pRead+2) & 0xf;
}

