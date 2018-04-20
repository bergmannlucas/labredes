/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#include <linux/ip.h>
#include <netinet/udp.h>

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

  unsigned char buff1[BUFFSIZE]; // buffer de recepcao

  int sockd;
  int on;
  struct ifreq ifr;
  struct iphdr *ipv4;
  struct udphdr *udp;

int main(int argc,char *argv[])
{
  int numBytes = 0;
  /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
  // De um "man" para ver os parametros.
  // htons: converte um short (2-byte) integer para standard network byte order.
  if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
     printf("Erro na criacao do socket.\n");
     exit(1);
  }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "enp4s0");
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	// recepcao de pacotes
	while (1) {
   	numBytes = recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		// impressão do conteudo - exemplo Endereco Destino e Endereco Origem
		if(buff1[5] == 0x32 && buff1[11] == 0x32) {
      printf("#####ETHERNET##### \n");
			printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
			printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);
			printf("Type: %x%x \n\n", buff1[12], buff1[13]);
			if(buff1[12] == 0x08 && buff1[13] == 0x00) {
				ipv4 = (struct iphdr*)&buff1[14];
				printf("#####IPV4##### \n");
				printf("Version : %d \n", ipv4->version);
				printf("IHL : %d \n", ipv4->ihl);
				printf("Type of service: %d \n", ipv4->tos);
				printf("Total length : %d\n", ipv4->tot_len);
				printf("Identification : %d \n", ipv4->id);
				printf("Fragment Offset : %d \n", ipv4->frag_off);
				printf("Ttl : %d\n", ipv4->ttl);
				printf("Protocol : %d\n", ipv4->protocol);
				printf("Checksum : %d\n", ipv4->check);
				printf("Source address : %s\n", inet_ntoa(*(struct in_addr *)&ipv4->saddr));
				printf("Destination address : %s\n\n", inet_ntoa(*(struct in_addr *)&ipv4->daddr));
        udp = (struct udphdr*)&buff1[34];
				printf("#####UDP##### \n");
				printf("Source port : %d \n", udp->source);
				printf("Destination port : %d \n", udp->dest);
				printf("Length : %d \n", udp->len);
        printf("Checksum : %d \n", udp->check);

        int i=42;
        FILE *fp = fopen("saida.txt", "w");
        if (fp == NULL) {
           printf ("Houve um erro ao abrir o arquivo.\n");
           return 1;
        }
        while(i < numBytes) {
          if(fwrite(&buff1[i],sizeof(char), 1, fp) != 1) {
            printf("Erro na escrita do arquivo");
          }
          i++;
        }
        fclose(fp);
			}
		}

	}
}
