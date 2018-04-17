/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens com struct          */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

unsigned char buff[1500];

void monta_pacote()
{
	// as struct estao descritas nos seus arquivos .h
	// por exemplo a ether_header esta no net/ethert.h
	// a struct ip esta descrita no netinet/ip.h
	struct ether_header *eth;

	// coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
	// onde inicia o header do ethernet.
	eth = (struct ether_header *) &buff[0];

	//Endereco Mac Destino
	eth->ether_dhost[0] = 0X70;
	eth->ether_dhost[1] = 0X8b;
	eth->ether_dhost[2] = 0Xcd;
	eth->ether_dhost[3] = 0Xe5;
	eth->ether_dhost[4] = 0X5d;
	eth->ether_dhost[5] = 0X32;

	//Endereco Mac Origem
	eth->ether_shost[0] = 0X70;
	eth->ether_shost[1] = 0X8b;
	eth->ether_shost[2] = 0Xcd;
	eth->ether_shost[3] = 0Xe5;
	eth->ether_shost[4] = 0X5d;
	eth->ether_shost[5] = 0X32;

 	eth->ether_type = htons(0X800);
}

int main(int argc,char *argv[])
{
	int sock, i;
	struct ifreq ifr;
	struct sockaddr_ll to;
	socklen_t len;
	unsigned char addr[6];

    /* Inicializa com 0 os bytes de memoria apontados por ifr. */
	memset(&ifr, 0, sizeof(ifr));

    /* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. D� um "man" para ver os par�metros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        exit(1);
 	}

	/* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_ifindex = 2; /* indice da interface pela qual os pacotes serao enviados */
	addr[0]=0x00;
	addr[0]=0x06;
	addr[0]=0x5B;
	addr[0]=0x28;
	addr[0]=0xAE;
	addr[0]=0x73;
	memcpy (to.sll_addr, addr, 6);
	len = sizeof(struct sockaddr_ll);

	monta_pacote();

	if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
			printf("sendto maquina destino.\n");
}
