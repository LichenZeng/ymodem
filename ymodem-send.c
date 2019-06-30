#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "ymodem.h"

int uart_fd = -1;
//int uart_fd2 = -1;

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

int openPort()
{
	uart_fd = open("/dev/ttyS12", O_RDWR);
	//uart_fd = open("/dev/ttyUSB0", O_RDWR | O_NONBLOCK | O_NOCTTY | O_NDELAY);
	if(uart_fd == -1) {
		printf("failure, could not open port.\n");
		return 0;
	} else {
		fcntl(uart_fd, F_SETFL, 0);
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

int writeBuf(int fd, char *buf, int len)
{
	int ret = write(fd, (void *)buf, len);
	return ret;
}

int readChar(uint8_t *chr)
{
	int result = read(uart_fd, chr, 1);
	return result;
}

int receive_byte(uint8_t *chr)
{
	return readChar(chr);
}

int send_byte(char chr)
{
	return writeBuf(uart_fd, &chr, 1);
}

int handle_after_recv_file_head()
{
	printf("Receive file head\n");
	return 0;
};

int handle_after_recv_packet(uint8_t *packet)
{
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
int32_t Receive_Byte(uint8_t *c, uint32_t timeout)
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
uint32_t Send_Byte (uint8_t c)
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
int32_t Receive_Packet (uint8_t *data, int32_t *length, uint32_t timeout)
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
	uint8_t file_ptr[FILE_NAME_LENGTH + FILE_SIZE_LENGTH + 1];

	memset(file_ptr, 0x0, FILE_NAME_LENGTH + FILE_SIZE_LENGTH + 1);
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

	packetSize = PACKET_TRANSMIT_SIZE;

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
	for (i = 0; i < (FILE_NAME_LENGTH-1); i++)
	{
		FileName[i] = sendFileName[i];
	}
	FileName[FILE_NAME_LENGTH-1] = '\0';
	CRC16_F = 1;

	/* Prepare first block */
	memset(packet_data, 0x0, PACKET_1K_SIZE + PACKET_OVERHEAD);
	Ymodem_PrepareIntialPacket(&packet_data[0], FileName, &sizeFile);


	/* Wait for 'C' */
	while (!((Receive_Byte(&receivedC[0], ACK_TIMEOUT_LONG) == 0) && (receivedC[0] == CRC16)));
	do
	{
		/* Send Packet */
		Ymodem_SendPacket(packet_data, PACKET_SIZE + PACKET_HEADER);

		/* Send CRC or Check Sum based on CRC16_F */
		if (CRC16_F)
		{
			tempCRC = Cal_CRC16(&packet_data[3], PACKET_SIZE);
			Send_Byte(tempCRC >> 8);
			Send_Byte(tempCRC & 0xFF);
		}
		else
		{
			tempCheckSum = CalChecksum(&packet_data[3], PACKET_SIZE);
			Send_Byte(tempCheckSum);
		}
		/* Wait for Ack and 'C' */
		if (Receive_Byte(&receivedC[0], ACK_TIMEOUT) == 0)
		{
			if (receivedC[0] == ACK)
			{
				/* Packet transfered correctly */
				ackReceived = 1;
			}
		}
		else
		{
			errors++;
		}
	} while (!ackReceived && (errors < RETRY_TIMES));

	if (errors >=  RETRY_TIMES)
	{
		return errors;
	}


	/* Wait for 'C' */
	while (!((Receive_Byte(&receivedC[0], ACK_TIMEOUT_LONG) == 0) && (receivedC[0] == CRC16)));

	buf_ptr = buf;
	size = sizeFile;
	blkNumber = 0x01;

	/* Here 1024 bytes package is used to send the packets */
	/* Resend packet if NAK  for a count of 10 else end of commuincation */
	while (size)
	{
		/* Prepare next packet */
		Ymodem_PreparePacket(buf_ptr, &packet_data[0], blkNumber, size);

		ackReceived = 0;
		receivedC[0] = 0;
		errors = 0;
		do
		{
			/* Send next packet */
			pktSize = PACKET_TRANSMIT_SIZE;
			Ymodem_SendPacket(packet_data, pktSize + PACKET_HEADER);

			/* Send CRC or Check Sum based on CRC16_F */
			if (CRC16_F)
			{
				tempCRC = Cal_CRC16(&packet_data[3], pktSize);
				Send_Byte(tempCRC >> 8);
				Send_Byte(tempCRC & 0xFF);
#ifdef PRINT_BUFFER
				int p;
				for(p=0; p<pktSize+5; p++) {
					printf("0x%02x  ", packet_data[p]);
				}
				printf("\n");
#endif
			}
			else
			{
				tempCheckSum = CalChecksum(&packet_data[3], pktSize);
				Send_Byte(tempCheckSum);
			}

			/* Wait for Ack */
			if ((Receive_Byte(&receivedC[0], ACK_TIMEOUT_LONG) == 0)  && (receivedC[0] == ACK))
			{
				ackReceived = 1;
				if (size > pktSize)
				{
					buf_ptr += pktSize;
					size -= pktSize;
					if (blkNumber == (MAX_SEND_SIZE/PACKET_TRANSMIT_SIZE))
					{
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
			}
		} while (!ackReceived && (errors < RETRY_TIMES));

		/* Resend packet if NAK  for a count of 10 else end of commuincation */
		if (errors >=  RETRY_TIMES)
		{
			return errors;
		}
	}


	ackReceived = 0;
	receivedC[0] = 0x00;
	errors = 0;
	do
	{
		/* Send (EOT); */
		Send_Byte(EOT);
		/* Wait for Ack */
		if ((Receive_Byte(&receivedC[0], ACK_TIMEOUT) == 0) && receivedC[0] == ACK)
		{
			ackReceived = 1;
		}
		else
		{
			errors++;
		}
	} while (!ackReceived && (errors < RETRY_TIMES));

	if (errors >= RETRY_TIMES)
	{
		return errors;
	}


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
		if (Receive_Byte(&receivedC[0], ACK_TIMEOUT) == 0)
		{
			if (receivedC[0] == ACK)
			{
				/* Packet transfered correctly */
				ackReceived = 1;
			}
		}
		else
		{
			errors++;
		}

	}while (!ackReceived && (errors < RETRY_TIMES));

	/* Resend packet if NAK  for a count of 10  else end of commuincation */
	if (errors >=  RETRY_TIMES)
	{
		return errors;
	}


	do
	{
		Send_Byte(EOT);
		/* Send (EOT); */
		/* Wait for Ack */
		if ((Receive_Byte(&receivedC[0], ACK_TIMEOUT) == 0) && receivedC[0] == ACK)
		{
			ackReceived = 1;
		}
		else
		{
			errors++;
		}
	} while (!ackReceived && (errors < RETRY_TIMES));

	if (errors >= RETRY_TIMES)
	{
		return errors;
	}
	return 0; /* file trasmitted successfully */
}


#define SYSFS_GPIO_EXPORT       "/sys/class/gpio/export"
#define SYSFS_GPIO_PIN          "33"
#define SYSFS_GPIO_DIR          "/sys/class/gpio/gpio33/direction"
#define SYSFS_GPIO_VAL          "/sys/class/gpio/gpio33/value"

void upgrade_gpio_init(void) {
	int fd = 0;
	fd = open(SYSFS_GPIO_EXPORT, O_WRONLY);
	if(fd == -1)
	{
		printf("ERR: Upgrade gpio open error.\n");
	}
	write(fd, SYSFS_GPIO_PIN,sizeof(SYSFS_GPIO_PIN));
	close(fd);

	fd = open(SYSFS_GPIO_DIR, O_WRONLY);
	if(fd == -1)
	{
		printf("ERR: Upgrade gpio direction open error.\n");
	}
	write(fd, "out", sizeof("out"));
	close(fd);
}

void upgrade_gpio_set(int val) {
	int IOfd = 0;
	IOfd = open(SYSFS_GPIO_VAL, O_WRONLY);
	if(IOfd == -1)
	{
		printf("ERR: Upgrade gpio value open error.\n");
	}
	if(!!val) {
		write(IOfd, "1", sizeof("1"));
	}else {
		write(IOfd, "0", sizeof("0"));
	}
}

int main(int argc, const char * argv[]) {
	FILE *stream = fopen(argv[1], "r");
	//FILE *stream = fopen("../test.txt", "r");
	if(!stream) {
		return -1;
	}

	fseek(stream, 0L, SEEK_END);
	uint32_t size = ftell(stream);
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
	upgrade_gpio_init();
	int ret = openPort();
	if(ret) {
#if 1
		upgrade_gpio_set(1);
		Ymodem_Transmit(buf, (const uint8_t *)argv[1], size);
		//Ymodem_Transmit(buf, "test.txt", size);
		upgrade_gpio_set(0);
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
