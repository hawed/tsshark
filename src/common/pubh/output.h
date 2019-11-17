/*
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

#ifndef _OUTPUT_H_
#define _OUTPUT_H_

const char*pidToStr(int pid);

const char* tidToStr(int tid);

void hexOut(char* buf, int len);

void outputTs(void *pstParseResult /*, int iInfoLevel*/, unsigned long uwPacketCount);

void outputPAT(void *pstParseResult);

void outputPMT(void *pstParseResult);

void outputCAT(void *pstParseResult);

void outputNIT(void *pstParseResult);

void outputBAT(void *pstParseResult);

void outputSDT(void *pstParseResult);

void outputEIT(void *pstParseResult);

void outputRST(void *pstParseResult);

void outputTDT(void *pstParseResult);

void outputTOT(void *pstParseResult);

void outputST(void *pstParseResult);


#endif //#ifndef _OUTPUT_H_
