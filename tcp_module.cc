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

void build_packet(Packet &p, ConnectionToStateMapping<TCPState> &Conn_to_State, unsigned int size, unsigned char flag);

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

  // List of connection to state mappings 
  ConnectionList<TCPState> clist;
  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
      cerr << "invalid event from Minet" << endl;
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        cerr << "\n---------------\n";
        cerr << "RECEIVED PACKET FROM BELOW:\n";

        Packet p;
        MinetReceive(mux,p);
        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        cerr << "estimated header len="<<tcphlen<<"\n";
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
        IPHeader ipl=p.FindHeader(Headers::IPHeader);
        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

        Connection c;

        ipl.GetDestIP(c.src);
        ipl.GetSourceIP(c.dest);
        ipl.GetProtocol(c.protocol);
        tcph.GetDestPort(c.srcport);
        tcph.GetSourcePort(c.destport); 

        cerr << "IP: " << c.src << " to " << c.dest << endl;
        cerr << "Port: " << c.srcport << " to " << c.destport << endl;

        unsigned short len;
        unsigned char tcp_len;
        unsigned char ip_len;
        unsigned char flag;
        unsigned int seqnum;


        ipl.GetTotalLength(len);
        ipl.GetHeaderLength(ip_len);
        tcph.GetHeaderLen(tcp_len);
        tcph.GetFlags(flag);
        tcph.GetSeqNum(seqnum);

        len -= (4*tcp_len + 4*ip_len);
        cerr << "Data Size: " << len << endl;
        Buffer &data = p.GetPayload().ExtractFront(len);

        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
        if(cs!=clist.end()) {
          cerr << "In connections list" << endl;  
          unsigned int cur_state = cs->state.GetState();
          cerr << "State: " << cur_state << endl;


          switch(cur_state) {
            case LISTEN: {
              cerr << "Entered LISTEN" << endl;
              if(IS_SYN(flag)) {
                cerr << "Received a SYN" << endl;
                cs->state.SetState(SYN_RCVD);
                cs->connection = c;
                cs->state.last_acked = cs->state.last_sent;
                cs->state.SetLastRecvd(seqnum + 1);
                cs->bTmrActive = true;
                cs->timeout = Time() + 8;
                cs->state.last_sent = cs->state.last_sent + 1;

                Packet p_send;
                unsigned char send_flag = 0;
                SET_SYN(send_flag);
                SET_ACK(send_flag);
                build_packet(p_send,*cs,send_flag,0);
                cerr << p_send << endl;
                MinetSend(mux,p_send);
              }
              break;
            }
            case SYN_RCVD: {
              cerr << "Entered SYN_RCVD" << endl;
              if(IS_SYN(flag)) {
                cerr << "Still SYN" << endl;
              }
              if(IS_ACK(flag)) {
                cerr << "Received an ACK" << endl;
                cs->state.SetState(ESTABLISHED);
                SockRequestResponse write(WRITE,
                        (*cs).connection,
                        data,
                        len,
                        EOK);
                MinetSend(sock,write);
              }
              break;
            }

          }
          

          // bool checksumok;


          cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID") << endl;
        }
        else {
          cerr << "Not in connections list" << endl;
        }

        cerr << "---------------\n";
        
      }
          //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        cerr << "\n---------------\n";
        SockRequestResponse s;
        SockRequestResponse response;
        MinetReceive(sock,s);
        cerr << "RECEIVED PACKET FROM ABOVE:\n";
        cerr << "Received Socket Request:" << s << endl;
        switch(s.type) {
          case ACCEPT: {
            // passive open from remote. The connection should be fully bound on
            // the local side and unbound on the remote side. The data, bytes count, and error
            // fields are ignored. The TCP module will do the passive open and immediately
            // return a STATUS with only the error code set. Whenever a connection arrives,
            // the TCP module will accept it and send a zero byte WRITE with the fully bound
            // connection. 
            cerr << "ACCEPT request" << endl;

            // Add connection state pair to connections list
            TCPState new_state(1,LISTEN,3);
            ConnectionToStateMapping<TCPState> Conn_to_State(s.connection,Time(),new_state,false);
            cerr << "New connection: " << Conn_to_State << endl;
            clist.push_back(Conn_to_State);

            // Send STATUS response
            response.connection = s.connection;
            response.type = STATUS;
            response.bytes = 0;
            response.error = EOK;
            MinetSend(sock,response);
            cerr << "Sent Accept response" << endl; 

            break;
          }

        }
        cerr << "---------------\n";
      }
    }
  }
  return 0;
}


void build_packet(Packet &p, ConnectionToStateMapping<TCPState> &Conn_to_State, unsigned int size, unsigned char flag) {
  IPHeader iph;
  TCPHeader tcph;
  Connection c = Conn_to_State.connection;
  int total_size = size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
  unsigned char nflag = 0;
  SET_ACK(nflag);
  SET_SYN(nflag);

  iph.SetSourceIP(c.src);
  iph.SetDestIP(c.dest);
  iph.SetProtocol(IP_PROTO_TCP);
  iph.SetTotalLength(total_size);
  p.PushFrontHeader(iph);
  tcph.SetSourcePort(c.srcport, p);
  tcph.SetDestPort(c.destport, p);
  tcph.SetFlags(nflag, p);
  tcph.SetHeaderLen(5,p);
  tcph.SetUrgentPtr(0,p);
  tcph.SetAckNum(Conn_to_State.state.GetLastRecvd(), p);
  tcph.SetWinSize(Conn_to_State.state.GetN(), p);
  tcph.SetSeqNum(Conn_to_State.state.GetLastSent()+1,p);
  tcph.RecomputeChecksum(p);
  p.PushBackHeader(tcph);
  cerr << iph << endl;
  cerr << tcph << endl;
}




