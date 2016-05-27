/******************************************************************************
 * Ymodem.c - Input the information of file:
 * 
 * Copyright (c) 2006-2012  KO
 * 
 * DESCRIPTION: - 实现Ymodem协议
 *     Input the description of file:
 * Author: FuDongQiang@2015/07/04
 * 
 * modification history
 *   ...
 ******************************************************************************/
#include "ymodem.h"
#include "stdio.h"
/*******************************************************************************/
/***********************************************
  协议介绍:
 ************************************************/
/*
   (1)开启是由接收方开启传输，它发一个大写字母C开启传输。然后进入等待（SOH）状态，如果没有回应，就会超时退出。
   (2)发送方开始时处于等待过程中，等待C。收到C以后，发送数据包开始信号:数据头+发送序号（00）+反码（FF）+“文件名”+“空格”+“文件大小”+“除去序号外，补满128字节”+CRC校验两个字节。进入等待（ACK）状态。
//最后两字节：这里需要注意，只有数据部分参与了效CRC验,不包括头和编码部分。
16位CRC效验，高字节在前，低字节在后
(3)
Ymodem协议分析

1、明确概念

一步一步来，先把概念搞清楚。

Ymodem协议是一种发送并等待的协议。即发送方发送一个数据包以后，都要等待接收方的确认。如果是ACK信号，则可以发送新的包。如果是NAK信号，则重发或者错误退出。

2、文件传输过程

文件传输过程的开启：

（1）开启是由接收方开启传输，它发一个大写字母C开启传输。然后进入等待（SOH）状态，如果没有回应，就会超时退出。

（2）发送方开始时处于等待过程中，等待C。收到C以后，发送（SOH）数据包开始信号:数据头+发送序号（00）+反码（FF）+“文件名”+“空格”+“文件大小”+“除去序号外，补满128字节”+CRC校验两个字节。进入等待（ACK）状态。
最后两字节：这里需要注意，只有数据部分参与了效CRC验,不包括头和编码部分。
16位CRC效验，高字节在前，低字节在后

（3）接收方收到以后，CRC校验满足，则发送ACK。发送方接收到ACK，又进入等待“文件传输开启”信号，即重新进入等待“C”的状态。

（4）前面接收方只是收到了一个文件名，现在正式开启文件传输，Ymodem支持128字节和1024字节一个数据包。128字节以（SOH）开始，1024字节以（STX）开始。

接收方又发出一个“C”信号，开始准备接收文件。进入等待“SOH”或者“STX”状态。

（5）发送方接收到“C”以后，发送数据包，（SOH）（01序号）（FE补码）（128位数据）（CRC校验），等待接收方“ACK”。

（6）文件发送完以后，发送方发出一个“EOT”信号，接收方也以“ACK”回应。

然后接收方会再次发出“C”开启另一次传输，若接着发送方会发出一个“全0数据包”，接收方“ACK”以后，本次通信正式结束。

（7）当然Ymodem相对于Xmodem改进的地方就在于传输再次开启以后，又可以发送另外一个文件，即一次传输允许发送多个文件，但这个特性我就不准备实现了。

大致流程
SENDER                                                      RECEIVER

"sending in batch mode etc."                                                    //1、发送方等待接收方发送"C"开启传输

C (command:rb)     //2、接收方发送"C"请求发送方传输                                

SOH 00 FF foo.c NUL[123] CRC CRC                                                //3、发送方响应接收方的请求，发送数据头
ACK                //4、接收方接受数据头成功，发送ACK，并再次发送"C"请求发送方开始正式的文件传输
C
SOH 01 FE Data[1024] CRC CRC                                                    //5、发送方发送数据包

ACK                //6、接收方成功接收到一个数据包，发送ACK，告诉发送方可以继续发送下一个数据包
STX 02 FD Data[1024] CRC CRC

ACK                //.

SOH 03 FC Data[128] CRC CRC

ACK                //.

SOH 04 FB Data[100] CPMEOF[28] CRC CRC                                          //n、发送方发送最后一个数据包，不足128个数据的补足128个

ACK                //.           

EOT                                                                             //n+1、发送方发送传输结束标志

ACK                //n+2、接收方ACK
C                  //n+3、如果接收方还想继续接收下一个文件，重新发送"C"

SOH 00 FF NUL[128] CRC CRC                                                      //n+4；发送方已经没有文件需要发送了，发送一个全零的数据包

ACK
*/
/*******************************************************************************/

/* Private function prototypes -----------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

int uart_fd = -1;

int setupPort(int fd, int baud, int data_bits, char event, int stop_bits, int parity, int hardware_control) {
	struct termios newtio, oldtio;

	if(tcgetattr(fd, &oldtio)  !=  0) {
		perror("SetupSerial 1");
		return -1;
	}

	bzero(&newtio, sizeof(newtio));
	newtio.c_cflag  |=  CLOCAL | CREAD;
	newtio.c_cflag &= ~CSIZE;

	switch(data_bits) {
		case 7:
			newtio.c_cflag |= CS7;
			break;
		case 8:
			newtio.c_cflag |= CS8;
			break;
	}

	switch(event) {
		case 'O':                     //奇校验
			newtio.c_cflag |= PARENB;
			newtio.c_cflag |= PARODD;
			newtio.c_iflag |= (INPCK | ISTRIP);
			break;
		case 'E':                     //偶校验
			newtio.c_iflag |= (INPCK | ISTRIP);
			newtio.c_cflag |= PARENB;
			newtio.c_cflag &= ~PARODD;
			break;
		case 'N':                    //无校验
			newtio.c_cflag &= ~PARENB;
			break;
	}

	switch(baud) {
		case 2400:
			cfsetispeed(&newtio, B2400);
			cfsetospeed(&newtio, B2400);
			break;
		case 4800:
			cfsetispeed(&newtio, B4800);
			cfsetospeed(&newtio, B4800);
			break;
		case 9600:
			cfsetispeed(&newtio, B9600);
			cfsetospeed(&newtio, B9600);
			break;
		case 57600:
			cfsetispeed(&newtio, B57600);
			cfsetospeed(&newtio, B57600);
			break;
		case 115200:
			cfsetispeed(&newtio, B115200);
			cfsetospeed(&newtio, B115200);
			break;
		default:
			cfsetispeed(&newtio, B9600);
			cfsetospeed(&newtio, B9600);
			break;
	}

	if(stop_bits == 1) {
		newtio.c_cflag &=  ~CSTOPB;
	} else if(stop_bits == 2) {
		newtio.c_cflag |=  CSTOPB;
	}
	newtio.c_cc[VTIME]  = 0;
	newtio.c_cc[VMIN] = 0;
	tcflush(fd, TCIFLUSH);
	if((tcsetattr(fd, TCSANOW, &newtio)) != 0) {
		perror("com set error");
		return -1;
	}
	return 1;
}




int openPort() {
	//uart_fd = open("/dev/pts/5", O_RDWR | O_NONBLOCK | O_NOCTTY | O_NDELAY);
	uart_fd = open("/dev/ttyUSB0", O_RDWR | O_NONBLOCK | O_NOCTTY | O_NDELAY);
	if(uart_fd == -1) {
		printf("failure, could not open port.\n");
		return 0;
	} else {
		//fcntl(uart_fd, F_SETFL, 0);
	}

	int success = setupPort(uart_fd, 115200, 8, 'N', 1, 0, 0);

	if(!success) {
		printf("failure, could not configure port.\n");
		return 0;
	}
	if(uart_fd <= 0) {
		printf("Connection attempt to port %s with %d baud, 8N1 failed, exiting.\n", "/dev/ttyUSB0", 115200);
		return 0;
	}
	return 1;
}

int writeBuf(int fd, char *buf, int len) {
	int ret = write(fd, (void *)buf, len);
	return ret;
}

int readChar(uint8_t *chr) {
	int result = read(uart_fd, chr, 1);
	return result;
}





int receive_byte(char *chr) {
	return readChar(chr);
}

int send_byte(char chr) {
	return writeBuf(uart_fd, &chr, 1);
}

int handle_after_recv_file_head() {
	printf("Receive file head\n");
	return 0;
};

int handle_after_recv_packet(uint8_t *packet) {
	printf("Receive file packet\n");
	return 0;
}
uint8_t file_name[FILE_NAME_LENGTH];

//最大接收和发送长度，超过此长度要求发送端终止传输
#define MAX_RECV_SIZE 4196000
#define MAX_SEND_SIZE 4196000
//定义自己的接收1Byte的函数,成功接收到一个Byte就返回1

#define RECEVIE_BYTE(RecvChar) receive_byte(RecvChar)
//定义自己发送1Byte的函数
#define SEND_BYTE(SendChar) send_byte(SendChar)
//定义自己接受到文件头后的操作
#define HANDLE_AFTER_RECV_FILE_HEAD() handle_after_recv_file_head()
//定义自己接受到一个数据包后的操作
#define HANDLE_AFTER_RECV_PACKET(pPacketData) handle_after_recv_packet(pPacketData)

#define IS_AF(c)  ((c >= 'A') && (c <= 'F'))
#define IS_af(c)  ((c >= 'a') && (c <= 'f'))
#define IS_09(c)  ((c >= '0') && (c <= '9'))
#define ISVALIDHEX(c)  IS_AF(c) || IS_af(c) || IS_09(c)
#define ISVALIDDEC(c)  IS_09(c)
#define CONVERTDEC(c)  (c - '0')
#define CONVERTHEX_alpha(c)  (IS_AF(c) ? (c - 'A'+10) : (c - 'a'+10))
#define CONVERTHEX(c)   (IS_09(c) ? (c - '0') : CONVERTHEX_alpha(c))
/* Private functions ---------------------------------------------------------*/

/**
 * @brief  Convert a string to an integer
 * @param  inputstr: The string to be converted
 * @param  intnum: The intger value
 * @retval 1: Correct
 *         0: Error
 */
uint32_t Str2Int(uint8_t *inputstr, int32_t *intnum)
{
	uint32_t i = 0, res = 0;
	uint32_t val = 0;

	if (inputstr[0] == '0' && (inputstr[1] == 'x' || inputstr[1] == 'X'))
	{
		if (inputstr[2] == '\0')
		{
			return 0;
		}
		for (i = 2; i < 11; i++)
		{
			if (inputstr[i] == '\0')
			{
				*intnum = val;
				/* return 1; */
				res = 1;
				break;
			}
			if (ISVALIDHEX(inputstr[i]))
			{
				val = (val << 4) + CONVERTHEX(inputstr[i]);
			}
			else
			{
				/* return 0, Invalid input */
				res = 0;
				break;
			}
		}
		/* over 8 digit hex --invalid */
		if (i >= 11)
		{
			res = 0;
		}
	}
	else /* max 10-digit decimal input */
	{
		for (i = 0;i < 11;i++)
		{
			if (inputstr[i] == '\0')
			{
				*intnum = val;
				/* return 1 */
				res = 1;
				break;
			}
			else if ((inputstr[i] == 'k' || inputstr[i] == 'K') && (i > 0))
			{
				val = val << 10;
				*intnum = val;
				res = 1;
				break;
			}
			else if ((inputstr[i] == 'm' || inputstr[i] == 'M') && (i > 0))
			{
				val = val << 20;
				*intnum = val;
				res = 1;
				break;
			}
			else if (ISVALIDDEC(inputstr[i]))
			{
				val = val * 10 + CONVERTDEC(inputstr[i]);
			}
			else
			{
				/* return 0, Invalid input */
				res = 0;
				break;
			}
		}
		/* Over 10 digit decimal --invalid */
		if (i >= 11)
		{
			res = 0;
		}
	}

	return res;
}

/**
 * @brief  Convert an Integer to a string
 * @param  str: The string
 * @param  intnum: The intger to be converted
 * @retval None
 */
void Int2Str(uint8_t* str, int32_t intnum)
{
	uint32_t i, Div = 1000000000, j = 0, Status = 0;

	for (i = 0; i < 10; i++)
	{
		str[j++] = (intnum / Div) + 48;

		intnum = intnum % Div;
		Div /= 10;
		if ((str[j-1] == '0') & (Status == 0))
		{
			j = 0;
		}
		else
		{
			Status++;
		}
	}
}

/**
 * @brief  Receive byte from sender
 * @param  c: Character
 * @param  timeout: Timeout
 * @retval 0: Byte received
 *         -1: Timeout
 */
static  int32_t Receive_Byte (uint8_t *c, uint32_t timeout)
{
	while (timeout-- > 0)
	{
		int val = RECEVIE_BYTE(c);
		if (val == 1)
		{
			return 0;
		}
	}
	return -1;
}

/**
 * @brief  Send a byte
 * @param  c: Character
 * @retval 0: Byte sent
 */
static uint32_t Send_Byte (uint8_t c)
{
	SEND_BYTE(c);
	return 0;
}

/**
 * @brief  Receive a packet from sender
 * @param  data
 * @param  length
 * @param  timeout
 *     0: end of transmission
 *    -1: abort by sender
 *    >0: packet length
 * @retval 0: normally return
 *        -1: timeout or packet error
 *         1: abort by user
 */
static int32_t Receive_Packet (uint8_t *data, int32_t *length, uint32_t timeout)
{
	uint16_t i, packet_size;
	uint8_t c;
	*length = 0;
	if (Receive_Byte(&c, timeout) != 0)
	{
		//接收超时
		return -1;
	}
	switch (c)
	{ 
		//Ymodem支持128字节和1024字节一个数据包。128字节以（ＳＯＨ）开始，１０２４字节以（ＳＴＸ）开始
		case SOH:
			packet_size = PACKET_SIZE;
			break;
		case STX:
			packet_size = PACKET_1K_SIZE;
			break;
			/*文件发送完以后，发送方发出一个“EOT”信号，接收方也以“ACK”回应。
			  然后接收方会再次发出“C”开启另一次传输，若接着发送方会发出一个“全0数据包”，
			  接收方“ACK”以后，本次通信正式结束*/
		case EOT:
			return 0;
			//传输结束以两个CA信号为标志
		case CA:
			if ((Receive_Byte(&c, timeout) == 0) && (c == CA))
			{
				*length = -1;
				return 0;
			}
			else
			{
				return -1;
			}
			//发送端终止传输
		case ABORT1:
		case ABORT2:
			return 1;
		default:
			return -1;
	}

	//开始接收一包数据
	*data = c;
	for (i = 1; i < (packet_size + PACKET_OVERHEAD); i ++)
	{
		if (Receive_Byte(data + i, timeout) != 0)
		{
			return -1;
		}
	}

	//看包序号与包序号反码是否相同，不相同表示该包发送错误，此处还可以加入检验校验码是否OK，保证数据传输正确
	if (data[PACKET_SEQNO_INDEX] != ((data[PACKET_SEQNO_COMP_INDEX] ^ 0xff) & 0xff))
	{
		return -1;
	}
	*length = packet_size;
	return 0;
}

/**
 * @brief  Receive a file using the ymodem protocol
 * @param  buf: Address of the first byte
 * @retval The size of the file，如果没有成功接收完一个文件，就返回0；否则返回接收到的文件长度
 */
int32_t Ymodem_Receive (uint8_t *buf)
{
	uint8_t packet_data[PACKET_1K_SIZE + PACKET_OVERHEAD], file_size[FILE_SIZE_LENGTH], *file_ptr, *buf_ptr;
	int32_t i, j, packet_length, session_done, file_done, packets_received, errors, session_begin, size = 0;

	for (session_done = 0, errors = 0, session_begin = 0; ;)
	{
		for (packets_received = 0, file_done = 0, buf_ptr = buf; ;)
		{
			switch (Receive_Packet(packet_data, &packet_length, NAK_TIMEOUT))
			{
				//Receive_Packet正常返回
				case 0:
					errors = 0;
					switch (packet_length)
					{
						/* Abort by sender ,Receive_Packet返回接收长度为-1，表示发送端终止传输*/
						case - 1:
							Send_Byte(ACK);
							return 0;
							/* End of transmission ,Receive_Packet返回接收长度为0，表示此次接收完成*/
						case 0:
							Send_Byte(ACK);
							file_done = 1;
							break;
							/* Normal packet */
						default:
							//检测包序号是否一致，不一致，说明接收端有包没有接收到，请求重新发送
							if ((packet_data[PACKET_SEQNO_INDEX] & 0xff) != (packets_received & 0xff))
							{
								Send_Byte(NAK);
							}
							else
							{
								//第一个包为文件头，包含文件名称和文件大小
								if (packets_received == 0)
								{
									/* Filename packet */
									if (packet_data[PACKET_HEADER] != 0)
									{
										/* Filename packet has valid data ，获取文件名*/
										for (i = 0, file_ptr = packet_data + PACKET_HEADER; (*file_ptr != 0) && (i < FILE_NAME_LENGTH);)
										{
											file_name[i++] = *file_ptr++;
										}
										file_name[i++] = '\0';
										for (i = 0, file_ptr ++; (*file_ptr != ' ') && (i < FILE_SIZE_LENGTH);)
										{
											file_size[i++] = *file_ptr++;
										}
										file_size[i++] = '\0';
										Str2Int(file_size, &size);

										/*如果文件大小超过最大允许接收大小，要求发送端终止传输*/
										if (size > (MAX_RECV_SIZE - 1))
										{
											/* End session */
											Send_Byte(CA);
											Send_Byte(CA);
											return -1;
										}

										//定义自己的接收到文件头后的处理动作
										HANDLE_AFTER_RECV_FILE_HEAD();

										//告诉发送方此包数据接收正确
										Send_Byte(ACK);
										//发送字母‘C’，告诉发送方文件头接收正确，可以正式开始文件传输
										Send_Byte(CRC16);
									}
									/* Filename packet is empty, end session */
									/*文件发送完以后，发送方发出一个“EOT”信号，接收方也以“ACK”回应。
									  然后接收方会再次发出“C”开启另一次传输，若接着发送方会发出一个“全0数据包”，
									  接收方“ACK”以后，本次通信正式结束*/
									else
									{
										Send_Byte(ACK);
										file_done = 1;
										session_done = 1;
										break;
									}
								}
								/* Data packet */
								else
								{
									memcpy(buf_ptr, packet_data + PACKET_HEADER, packet_length);

									//接收到一个数据包后的处理函数
									HANDLE_AFTER_RECV_PACKET(buf_ptr);
									/*
									//根据处理函数的返回结果确定是要终止传输还是继续
									if()
									{
									Send_Byte(CA);
									Send_Byte(CA);
									return -2;   
									}
									*/

									Send_Byte(ACK);
								}
								packets_received ++;
								session_begin = 1;
							}
					}
					break;
					//Receive_Packet非正常返回，发送端终止了传输
				case 1:
					Send_Byte(CA);
					Send_Byte(CA);
					return -3;
					//Receive_Packet非正常返回，接收超时或者包错误
				default:
					if (session_begin > 0)
					{
						errors ++;
					}
					if (errors > MAX_ERRORS)
					{
						Send_Byte(CA);
						Send_Byte(CA);
						return 0;
					}
					//向发送端请求开始文件传输，用一个大写字母C开启传输。然后进入等待（SOH）状态
					Send_Byte(CRC16);
					break;
			}
			if (file_done != 0)
			{
				break;
			}
		}
		if (session_done != 0)
		{
			break;
		}
	}
	return (int32_t)size;
}


//发送部分
/**
 * @brief  Transmit a data packet using the ymodem protocol
 * @param  data
 * @param  length
 * @retval None
 */
void Ymodem_SendPacket(uint8_t *data, uint16_t length)
{
	uint16_t i;
	i = 0;
	while (i < length)
	{
		Send_Byte(data[i]);
		i++;
	}
}

/**
 * @brief  check response using the ymodem protocol
 * @param  buf: Address of the first byte
 * @retval The size of the file
 */
int32_t Ymodem_CheckResponse(uint8_t c)
{
	return 0;
}

/**
 * @brief  Prepare the first block
 * @param  timeout
 *     0: end of transmission
 */
void Ymodem_PrepareIntialPacket(uint8_t *data, const uint8_t* fileName, uint32_t *length)
{
	uint16_t i, j;
	uint8_t file_ptr[10];

	memset(file_ptr, 0x0, 10);
	/* Make first three packet */
	data[0] = SOH;
	data[1] = 0x00;
	data[2] = 0xff;

	/* Filename packet has valid data */
	for (i = 0; (fileName[i] != '\0') && (i < FILE_NAME_LENGTH);i++)
	{
		data[i + PACKET_HEADER] = fileName[i];
	}

	data[i + PACKET_HEADER] = 0x00;

	Int2Str (file_ptr, *length);
	for (j =0, i = i + PACKET_HEADER + 1; file_ptr[j] != '\0' ; )
	{
		data[i++] = file_ptr[j++];
	}

	for (j = i; j < PACKET_SIZE + PACKET_HEADER; j++)
	{
		data[j] = 0;
	}
}


/******************************************************************************
 * FUNCTION: Ymodem_PreparePacket ( )
 * DESCRIPTION: 
 *    Input the description of function: 
 * Input Parameters: 待发送数据，发送数据放置的包，包编号，待发送数据长度
 * Output Parameters: 
 * Returns Value: 
 * 
 * Author: FuDongQiang @ 2015/07/04
 * 
 * modification history
 *   ...
 ******************************************************************************/
void Ymodem_PreparePacket(uint8_t *SourceBuf, uint8_t *data, uint8_t pktNo, uint32_t sizeBlk)
{
	uint16_t i, size, packetSize;
	uint8_t* file_ptr;

	/* Make first three packet */
	//packetSize = sizeBlk >= PACKET_1K_SIZE ? PACKET_1K_SIZE : PACKET_SIZE;
	packetSize = PACKET_SIZE;
	size = sizeBlk < packetSize ? sizeBlk :packetSize;
	if (packetSize == PACKET_1K_SIZE)
	{
		data[0] = STX;
	}
	else
	{
		data[0] = SOH;
	}
	data[1] = pktNo;
	data[2] = (~pktNo);
	file_ptr = SourceBuf;

	/* Filename packet has valid data */
	for (i = PACKET_HEADER; i < size + PACKET_HEADER;i++)
	{
		data[i] = *file_ptr++;
	}
	//不足一个包的要补足一个包
	if ( size  <= packetSize)
	{
		for (i = size + PACKET_HEADER; i < packetSize + PACKET_HEADER; i++)
		{
			data[i] = 0x1A; /* EOF (0x1A) or 0x00 */
		}
	}
}

/**
 * @brief  Update CRC16 for input byte
 * @param  CRC input value 
 * @param  input byte
 * @retval None
 */
uint16_t UpdateCRC16(uint16_t crcIn, uint8_t byte)
{
	uint32_t crc = crcIn;
	uint32_t in = byte|0x100;
	do
	{
		crc <<= 1;
		in <<= 1;
		if(in&0x100)
			++crc;
		if(crc&0x10000)
			crc ^= 0x1021;
	}
	while(!(in&0x10000));
	return crc&0xffffu;
}


/**
 * @brief  Cal CRC16 for YModem Packet
 * @param  data
 * @param  length
 * @retval None
 */
uint16_t Cal_CRC16(const uint8_t* data, uint32_t size)
{
	uint32_t crc = 0;
	const uint8_t* dataEnd = data+size;
	while(data<dataEnd)
		crc = UpdateCRC16(crc,*data++);

	crc = UpdateCRC16(crc,0);
	crc = UpdateCRC16(crc,0);
	return crc&0xffffu;
}

/**
 * @brief  Cal Check sum for YModem Packet
 * @param  data
 * @param  length
 * @retval None
 */
uint8_t CalChecksum(const uint8_t* data, uint32_t size)
{
	uint32_t sum = 0;
	const uint8_t* dataEnd = data+size;
	while(data < dataEnd )
		sum += *data++;
	return sum&0xffu;
}

/**
 * @brief  Transmit a file using the ymodem protocol
 * @param  buf: Address of the first byte
 * @retval The size of the file
 */
uint8_t Ymodem_Transmit(uint8_t *buf, const uint8_t* sendFileName, uint32_t sizeFile)
{
	uint8_t packet_data[PACKET_1K_SIZE + PACKET_OVERHEAD];
	uint8_t FileName[FILE_NAME_LENGTH];
	uint8_t *buf_ptr, tempCheckSum ;
	uint16_t tempCRC, blkNumber;
	uint8_t receivedC[2], CRC16_F = 0, i;
	uint32_t errors, ackReceived, size = 0, pktSize;

	errors = 0;
	ackReceived = 0;
	for (i = 0; i < (FILE_NAME_LENGTH - 1); i++)
	{
		FileName[i] = sendFileName[i];
	}
	FileName[FILE_NAME_LENGTH-1] = '\0';
	CRC16_F = 1;       

	/* Prepare first block */
	printf("Prepare Start Packet\n");
	memset(packet_data, 0x0, PACKET_1K_SIZE + PACKET_OVERHEAD);
	Ymodem_PrepareIntialPacket(&packet_data[0], FileName, &sizeFile);

	int count = 1;
	do 
	{
		printf("Send Start Packet\n");
		/* Send Packet */
		Ymodem_SendPacket(packet_data, PACKET_SIZE + PACKET_HEADER);
		/* Send CRC or Check Sum based on CRC16_F */
		if (CRC16_F)
		{
			printf("CRC16_F\n");
			tempCRC = Cal_CRC16(&packet_data[3], PACKET_SIZE);
			Send_Byte(tempCRC >> 8);
			Send_Byte(tempCRC & 0xFF);
		}
		else
		{
			printf("CHECKSUM\n");
			tempCheckSum = CalChecksum (&packet_data[3], PACKET_SIZE);
			Send_Byte(tempCheckSum);
		}
		/* Wait for Ack and 'C' */
		if (Receive_Byte(&receivedC[0], 100000) == 0)  
		{
			printf("Receive Byte 1 -> 0x%02x\n", receivedC[0]);
			if (receivedC[0] == ACK)
			{ 
				printf("Receive ACK - 1\n");
				/* Packet transfered correctly */
				ackReceived = 1;
			}
		}
		else
		{
			errors++;
		}
	}while (!ackReceived && (errors < 0x0A));
#if 1
	if (errors >=  0x0A)
	{
		printf("errors return\n");
		return errors;
	}
#endif
	buf_ptr = buf;
	size = sizeFile;
	blkNumber = 0x01;
	/* Here 1024 bytes package is used to send the packets */


	/* Resend packet if NAK  for a count of 10 else end of commuincation */
	while (size)
	{
		printf("Send packet: frame->%d\n", blkNumber);
		/* Prepare next packet */
		Ymodem_PreparePacket(buf_ptr, &packet_data[0], blkNumber, size);
		ackReceived = 0;
		receivedC[0] = 0;
		errors = 0;
		do
		{
			/* Send next packet */
#if 0
			if (size >= PACKET_1K_SIZE)
			{
				pktSize = PACKET_1K_SIZE;

			}
			else
			{
				pktSize = PACKET_SIZE;
			}
#endif

			pktSize = PACKET_SIZE;
			Ymodem_SendPacket(packet_data, pktSize + PACKET_HEADER);
			/* Send CRC or Check Sum based on CRC16_F */
			/* Send CRC or Check Sum based on CRC16_F */
			if (CRC16_F)
			{
				tempCRC = Cal_CRC16(&packet_data[3], pktSize);
				Send_Byte(tempCRC >> 8);
				Send_Byte(tempCRC & 0xFF);
				int p;
				for(p=0; p<pktSize+5; p++) {
					printf("0x%02x  ", packet_data[p]);
				}
				printf("\n");
			}
			else
			{
				tempCheckSum = CalChecksum (&packet_data[3], pktSize);
				Send_Byte(tempCheckSum);
			}

			/* Wait for Ack */
			if ((Receive_Byte(&receivedC[0], 10000000) == 0)  && (receivedC[0] == ACK))
			{
				printf("Receive Byte 2 -> 0x%02x\n", receivedC[0]);
				printf("Receive ACK - 2\n");
				ackReceived = 1;  
				if (size > pktSize)
				{
					buf_ptr += pktSize;  
					size -= pktSize;
					if (blkNumber == (MAX_SEND_SIZE/128))
					{
						printf("Error: Max Send Size\n");
						return 0xFF; /*  error */
					}
					else
					{
						blkNumber++;
					}
				}
				else
				{
					buf_ptr += pktSize;
					size = 0;
				}
			}
			else
			{
				errors++;
				printf("Send Packet Error : %d\n", errors);
			}
		}while(!ackReceived && (errors < 0x0A));
		/* Resend packet if NAK  for a count of 10 else end of commuincation */
#if 1
		if (errors >=  0x0A)
		{
			return errors;
		}
#endif
	}
	ackReceived = 0;
	receivedC[0] = 0x00;
	errors = 0;
	do 
	{
		Send_Byte(EOT);
		/* Send (EOT); */
		/* Wait for Ack */
		printf("Send EOT, Wait ACK\n");
		if ((Receive_Byte(&receivedC[0], 10000) == 0)  && receivedC[0] == ACK)
		{
			printf("Receive ACK - 3\n");
			ackReceived = 1;  
		}
		else
		{
			errors++;
		}
	}while (!ackReceived);// && (errors < 0x0A));
#if 1
	if (errors >=  0x0A)
	{
		printf("Return errors 968\n");
		return errors;
	}
#endif

	printf("Send Last packet\n");

	/* Last packet preparation */
	ackReceived = 0;
	receivedC[0] = 0x00;
	errors = 0;

	packet_data[0] = SOH;
	packet_data[1] = 0;
	packet_data [2] = 0xFF;

	for (i = PACKET_HEADER; i < (PACKET_SIZE + PACKET_HEADER); i++)
	{
		packet_data [i] = 0x00;
	}

	do 
	{
		/* Send Packet */
		Ymodem_SendPacket(packet_data, PACKET_SIZE + PACKET_HEADER);
		/* Send CRC or Check Sum based on CRC16_F */
		tempCRC = Cal_CRC16(&packet_data[3], PACKET_SIZE);
		Send_Byte(tempCRC >> 8);
		Send_Byte(tempCRC & 0xFF);

		/* Wait for Ack and 'C' */
		if (Receive_Byte(&receivedC[0], 10000) == 0)  
		{
			if (receivedC[0] == ACK)
			{ 
				printf("Receive ACK - 4\n");
				/* Packet transfered correctly */
				ackReceived = 1;
			}
		}
		else
		{
			errors++;
		}

	}while (!ackReceived && (errors < 0x0A));
	/* Resend packet if NAK  for a count of 10  else end of commuincation */
#if 1
	if (errors >=  0x0A)
	{
		return errors;
	}  
#endif

	do 
	{
		Send_Byte(EOT);
		/* Send (EOT); */
		/* Wait for Ack */
		if ((Receive_Byte(&receivedC[0], 10000) == 0)  && receivedC[0] == ACK)
		{
			ackReceived = 1;  
		}
		else
		{
			errors++;
		}
	}while (!ackReceived && (errors < 0x0A));
#if 1
	if (errors >=  0x0A)
	{
		return errors;
	}
#endif
	return 0; /* file trasmitted successfully */
}

int main() {
	FILE *stream = fopen("../class-diagram.png", "r");
	if(!stream) {
		return -1;
	}

	fseek(stream, 0L, SEEK_END);
	long size = ftell(stream);
	if(size<=0) {
		return -1;
	}
	fseek(stream, 0L, SEEK_SET);
	uint8_t *buf = (uint8_t *)malloc(size);
	long count = fread(buf, 1, size, stream);
	if(count != size) {
		return -1;
	}

	fclose(stream);
	int ret = openPort();
	if(ret) {
#if 1
		Ymodem_Transmit(buf, "class-diagram.png", size);
#else
		uint8_t buf2[] = { 0x1, 0x2, 0x3, 0x4, 0x5 };
		Ymodem_Transmit(buf2, "teswt.txt", 5);
#endif
	}
#if 0
	while (1) {
		uint8_t c;
		if(Receive_Byte(&c, 1) == 0) {
		printf("\n");
			printf("Receive char: %c\n", c);
		}
		printf("Receive no char\n");
		usleep(1000000);
	}
#endif
	return 0;
}
