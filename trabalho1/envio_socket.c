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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define DEFAULT_IF "eth0" // interface padrao se n for passada por parametro
#define MY_DEST_MAC0 0x70
#define MY_DEST_MAC1 0x8b
#define MY_DEST_MAC2 0xcd
#define MY_DEST_MAC3 0xe5
#define MY_DEST_MAC4 0x5d
#define MY_DEST_MAC5 0x32

// para filtrar no wireshark
// eth.dst == 70:8b:cd:e5:5d:32 and eth.src == 70:8b:cd:e5:5d:32

// tamanho limite do arquivo 1471 bytes, a partir dai fragmentacao!

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

char ifName[IFNAMSIZ];
unsigned char buff[1500];
struct ifreq ifr;
struct ifreq if_ip;
char dadosArquivo[1460];
int tamanhoPacote;

/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}


void monta_pacote(int opcao) {
  // as struct estao descritas nos seus arquivos .h
  // por exemplo a ether_header esta no net/ethert.h
  // a struct ip esta descrita no netinet/ip.h
  struct ether_header *eth;
  struct iphdr *ipv4;
  struct udphdr *udp;
  struct tcphdr *tcp;

  // coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
  // onde inicia o header do ethernet.
  eth = (struct ether_header *) &buff[0];
  memset(buff, 0, 1500);
  //Endereco Mac Destino
  eth->ether_dhost[0] = MY_DEST_MAC0;
  eth->ether_dhost[1] = MY_DEST_MAC1;
  eth->ether_dhost[2] = MY_DEST_MAC2;
  eth->ether_dhost[3] = MY_DEST_MAC3;
  eth->ether_dhost[4] = MY_DEST_MAC4;
  eth->ether_dhost[5] = MY_DEST_MAC5;

  //Endereco Mac Origem
  eth->ether_shost[0] = MY_DEST_MAC0;
  eth->ether_shost[1] = MY_DEST_MAC1;
  eth->ether_shost[2] = MY_DEST_MAC2;
  eth->ether_shost[3] = MY_DEST_MAC3;
  eth->ether_shost[4] = MY_DEST_MAC4;
  eth->ether_shost[5] = MY_DEST_MAC5;

  eth->ether_type = htons(0X800);

  tamanhoPacote += sizeof(struct ether_header);

  // coloca o ponteiro do header ip apontando para a 14. posicao do buffer
  // onde inicia o header do ip.
  ipv4 = (struct iphdr*)&buff[14];
  ipv4->ihl = 5;
  ipv4->version = 4;
  ipv4->tos = 16;
  ipv4->id = htons(54321); //htons(rand());
  ipv4->ttl = 64;
  if(opcao == 1 || opcao == 3) {ipv4->protocol = 17;} // UDP
  else {ipv4->protocol = 6;} //TCP
  ipv4->saddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)); // IP ORIGEM
  ipv4->daddr = ipv4->saddr; // IP DESTINO inet_addr("192.168.25.19")
  ipv4->check = 0;
  ipv4->tot_len = htons(tamanhoPacote - sizeof(struct ether_header));
  ipv4->check = in_cksum((unsigned short *)ipv4, sizeof(struct iphdr));;
  tamanhoPacote += sizeof(struct iphdr);

  if(opcao == 1 || opcao == 3) {

    // coloca o ponteiro do header udp apontando para a 34. posicao do buffer
    // onde inicia o header do udp.
    udp = (struct udphdr *) (buff + sizeof(struct iphdr) + sizeof(struct ether_header));
    char *dataFrame = (char *) (buff + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
    // Copia os dados do arquivo para o dataFrame
    strcpy(dataFrame, dadosArquivo);
    udp->source = htons(23451);
    udp->dest = htons(23452);
    tamanhoPacote += sizeof(struct udphdr);
    tamanhoPacote += strlen(dataFrame);
    udp->len = htons(sizeof(struct udphdr) + strlen(dadosArquivo));
    udp->check = 0;

  } else if(opcao == 2) {
    /*
    tcp = (struct tcphdr *) (buff + sizeof(struct iphdr) + sizeof(struct ether_header));
    char *dataFrame = (char *) (buff + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    strcpy(dataFrame, dadosArquivo);
    tcp->dest = htons(23452);
    tcp->seq = 0;
    tcp->ack_seq = 0;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->check = 0;
    tcp->window = htons(5840);
    tcp->check = 0;
    tcp->urg_ptr = 0;
    tamanhoPacote += sizeof(struct tcphdr);
    tamanhoPacote += strlen(dataFrame);
    */
    printf("Função desabilitada!\n\n");
    exit(1);

  } else if(opcao == 3) {
    printf("Função desabilitada!\n\n");
    exit(1);
  } else {
    printf("Função desabilitada!\n\n");
    exit(1);
  }
}

int main(int argc, char*argv[])
{
  int sock, i;
  struct sockaddr_ll to;
  socklen_t len;
  unsigned char addr[6];

  int escolha; // Menu

  if(argc > 1) {
    strcpy(ifName, argv[1]);
  } else {
    strcpy(ifName, DEFAULT_IF);
    printf("Utilizando interface padrão eth0!\n\n");
  }

  // Inicializa com 0 os bytes de memoria apontados por ifr.
	(&ifr, 0, sizeof(ifr));

  // Arquivo - Begin
  char *buffer;
  FILE *fp;
  size_t size = 0;

  fp = fopen("teste.txt", "r");
  // Vai p/ final do arquivo
  fseek(fp, 0, SEEK_END);
  // Pega o tamanho do arquivo
  size = ftell(fp);
  // Volta p/ inicio do arquivo
  rewind(fp);
  // Aloca espaço no buffer com o tamanho do arquivo
  buffer = malloc((size + 1) * sizeof(*buffer));
  // le o arquivo até o fim
  fread(buffer, size, 1, fp);
  buffer[size] = '\0';
  // Passa o conteudo do arquivo/buffer para variavel global dadosArquivo
  strcpy(dadosArquivo, buffer);
  // Arquivo - End

  // Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. De um "man" para ver os parametros.
  // htons: converte um short (2-byte) integer para standard network byte order.
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
    printf("Erro na criacao do socket.\n");
    exit(1);
 	}

  // Pega o index da interface
  //memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
  if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    perror("SIOCGIFINDEX");

  // Para pegar o IP da maquina destino e origem! no monta_pacote()
  memset(&if_ip, 0, sizeof(struct ifreq));
  strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
  if (ioctl(sock, SIOCGIFADDR, &if_ip) < 0)
    perror("SIOCGIFADDR");


  // Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket.
	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_ifindex = ifr.ifr_ifindex; // indice da interface pela qual os pacotes serao enviados
  to.sll_halen = 6;
	addr[0]=MY_DEST_MAC0;
	addr[0]=MY_DEST_MAC1;
	addr[0]=MY_DEST_MAC2;
	addr[0]=MY_DEST_MAC3;
	addr[0]=MY_DEST_MAC4;
	addr[0]=MY_DEST_MAC5;
	memcpy (to.sll_addr, addr, 6);
	len = sizeof(struct sockaddr_ll);

  printf("\n ################################################### ");
  printf("\nTrabalho 1 LAB-REDES");
  printf("\n 1 - Enviar utilizando IPv4 e UDP ");
  printf("\n 2 - Enviar utilizando IPv4 e TCP ");
  printf("\n 3 - Enviar utilizando IPv6 e UDP ");
  printf("\n 4 - Enviar utilizando IPv6 e TCP ");
  printf("\n 5 - Fechar Programa ");
  printf("\n\n Escolha uma opcao: ");
  scanf("%d",&escolha);

  switch(escolha) {
      case 1: monta_pacote(1);
              break;
      case 2: monta_pacote(2);
              break;
      case 3: monta_pacote(3);
              break;
      case 4: monta_pacote(4);
              break;
      case 5: printf("\nFinalizando ferramenta...\n\n");
              exit(0);
      default: printf("\nOpção inválida!..\n\n");
              break;
  }

  if(sendto(sock, (char *) buff, tamanhoPacote, 0, (struct sockaddr*) &to, len)<0) {
    printf("sendto maquina destino.\n");
  }
}
