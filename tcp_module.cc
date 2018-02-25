#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"

#include "tcpstate.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;


int main(int argc, char *argv[])
{
  MinetHandle mux, sock;

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      cerr << "invalid event from Minet" << endl;
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        Packet p;
        MinetReceive(mux,p);
        cerr << "received packet from below\n";
        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        cerr << "estimated header len="<<tcphlen<<"\n";
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
        IPHeader ipl=p.FindHeader(Headers::IPHeader);
        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

        Connection c;

        ipl.GetDestIP(c.dest);
        ipl.GetSourceIP(c.src);
        ipl.GetProtocol(c.protocol);
        tcph.GetDestPort(c.destport);
        tcph.GetSourcePort(c.srcport); 

        ConnectionList<TCPState> clist;
        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
        unsigned short len;
        unsigned char tcp_len;
        unsigned char ip_len;

        ipl.GetTotalLength(len);
        ipl.GetHeaderLength(ip_len);
        tcph.GetHeaderLen(tcp_len);

        len -= (4*tcp_len + 4*ip_len);

        // bool checksumok;

        Buffer &data = p.GetPayload().ExtractFront(len);
        // SockRequestResponse write(WRITE,
        //             (*cs).connection,
        //             data,
        //             len,
        //             EOK);

        SockRequestResponse write (WRITE,(*cs).connection, data, len, EOK);

        MinetSend(sock,write);

        // cs = clist.FindMatching(c);
        // if (cs!=clist.end()) {
        //     tcph.GetLength(len);
        //     len-=TCP_HEADER_LENGTH;
        //     Buffer &data = p.GetPayload().ExtractFront(len);
        //     SockRequestResponse write(WRITE,
        //             (*cs).connection,
        //             data,
        //             len,
        //             EOK);
        //     if (!checksumok) {
        //       MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
        //     }
        //     MinetSend(sock,write);
        //   } else {
        //     MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
        //     IPAddress source; iph.GetSourceIP(source);
        //     ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
        //     MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
        //     MinetSend(mux, error);
        //   }


        cerr << "IP: "<<c.src<< " to "<<c.dest;
        cerr << "Port "<<c.srcport<< " to "<<c.destport;

        // cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
        // cerr << "TCP Header is "<<tcph << " and ";

        cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
        
      }
          //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "received packet from above\n";
        cerr << "Received Socket Request:" << s << endl;
      }
    }
  }
  return 0;
}
