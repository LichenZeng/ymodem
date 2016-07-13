#ifndef _YMODEM_H_
#define _YMODEM_H_
#include <stdint.h>

#define PACKET_SEQNO_INDEX      (1)
#define PACKET_SEQNO_COMP_INDEX (2)

#define PACKET_HEADER           (3)                                 //包头长度，包起始+包序号+包序号补码
#define PACKET_TRAILER          (2)                                 //包尾，两字节校验和
#define PACKET_OVERHEAD         (PACKET_HEADER + PACKET_TRAILER)
#define PACKET_SIZE             (128)
#define PACKET_1K_SIZE          (1024)
#define PACKET_TRANSMIT_SIZE 		PACKET_1K_SIZE //WEI --> 用来指定发送单帧数据长度

#define FILE_NAME_LENGTH        (64)
#define FILE_SIZE_LENGTH        (16)

#define SOH                     (0x01)  /* start of 128-byte data packet */
#define STX                     (0x02)  /* start of 1024-byte data packet */
#define EOT                     (0x04)  /* end of transmission */
#define ACK                     (0x06)  /* acknowledge */
#define NAK                     (0x15)  /* negative acknowledge */
#define CA                      (0x18)  /* two of these in succession aborts transfer */
#define CRC16                   (0x43)  /* 'C' == 0x43, request 16-bit CRC */

#define ABORT1                  (0x41)  /* 'A' == 0x41, abort by user */
#define ABORT2                  (0x61)  /* 'a' == 0x61, abort by user */

#define RETRY_TIMES 		(0x0A)
#define ACK_TIMEOUT             (1000000) //WEI --> 用来指定一般延时长度
#define ACK_TIMEOUT_LONG        (100000000) //WEI --> 用来指定长时间延时长度
#define NAK_TIMEOUT             (0x10000000)
#define MAX_ERRORS              (5)

int32_t Ymodem_Receive (uint8_t *);
uint8_t Ymodem_Transmit (uint8_t *,const  uint8_t* , uint32_t );

#endif  /* _YMODEM_H_ */
