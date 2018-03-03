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

enum flag_state { SYN = 0,
                  SYNACK = 1,
                  ACK = 2,
                  PSH = 3,
                  FIN = 4,
                  RST = 5, };

void build_packet(Packet &p, ConnectionToStateMapping<TCPState> &Conn_to_State, int size, flag_state flag_s);

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
        unsigned char flag = 0;
        unsigned int seqnum;
        unsigned int acknum;
        unsigned short win_size;
        unsigned short urgent;
        bool checksum;

        ipl.GetTotalLength(len);
        ipl.GetHeaderLength(ip_len);
        tcph.GetHeaderLen(tcp_len);
        tcph.GetFlags(flag);
        tcph.GetSeqNum(seqnum);
        tcph.GetAckNum(acknum);
        tcph.GetWinSize(win_size);
        tcph.GetUrgentPtr(urgent);
        checksum = tcph.IsCorrectChecksum(p);

        cerr << "Checksum is " << (checksum ? "VALID" : "INVALID") << endl;

        len -= (4*tcp_len + 4*ip_len);
        cerr << "Data Size: " << len << endl;
        Buffer &data = p.GetPayload().ExtractFront(len);

        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
        if(cs == clist.end()) {
          cerr << "Not in connections list" << endl;
        }
        else {
          cerr << "In connections list" << endl;  
        }

        unsigned int cur_state = cs->state.GetState();
        cerr << "State: " << cur_state << endl;
        cerr << cs->connection << endl;


        switch(cur_state) {
          case LISTEN: {
            cerr << "Entered LISTEN" << endl;
            if(IS_SYN(flag)) {
              cerr << "Received a SYN" << endl;

              /*
              CS is a pointer to a connection state mapping
              Connection to State mapping class:
                Connection connection
                Time timeout
                STATE state
                bool bTmrActive  
              */

              cs->connection = c;
              cs->timeout = Time() + 10;
              cs->state.SetState(SYN_RCVD);
              cs->state.SetLastRecvd(seqnum+1);
              cs->state.SetLastAcked(cs->state.GetLastSent());
              cs->bTmrActive = true;
              
              Packet p_send;
              build_packet(p_send,*cs,0,SYNACK);
              MinetSend(mux,p_send);
              // Eventually replace sleep with a timeout
              sleep(2);
              MinetSend(mux,p_send);
              cs->state.SetLastSent(cs->state.GetLastSent()+1);
            }
            break;
          }
          case SYN_RCVD: {
            cerr << "Entered SYN_RCVD" << endl;
            if(IS_ACK(flag)) {
              cerr << "Received an ACK" << endl;

              cs->state.SetState(ESTABLISHED);
              cs->state.SetLastRecvd(cs->state.GetLastRecvd() + len);
              cs->state.SetLastAcked(acknum);
              // cs->state.SetSendRwnd(win_size);
              cs->bTmrActive = false;

              // Send WRITE response
              // SockRequestResponse response;
              // response.connection = cs->connection;
              // response.type = WRITE;
              // response.data = data;
              // response.bytes = len;
              // response.error = EOK;
              // MinetSend(sock,response);
            }  
            break;
          }
            case ESTABLISHED: {
              cerr << "Entered ESTABLISHED" << endl;

              if(IS_PSH(flag)) {
                cerr << "Received data" << endl;
                cerr << "data:\n" << data << endl;

                cerr << "seqnum: " << seqnum << endl;
                if(seqnum == cs->state.GetLastRecvd()) {
                  cerr << "In order Packet" << endl;
                  cerr << "Old Last received: " << cs->state.GetLastRecvd() << endl; 
                  cs->state.SetLastRecvd(seqnum+len);
                  cerr << "New Last received: " << cs->state.GetLastRecvd() << endl;

                  Packet p_send;
                  build_packet(p_send,*cs,0,ACK);
                  MinetSend(mux,p_send);

                  // Send WRITE response
                  // SockRequestResponse response;
                  // response.connection = cs->connection;
                  // response.type = WRITE;
                  // response.data = data;
                  // response.bytes = len;
                  // response.error = EOK;
                  // MinetSend(sock,response);

                }
                else {
                  cerr << "Out of order Packet" << endl;
                }

              }
              else if(IS_FIN(flag)) {
                cerr << "Close Connection" << endl;
                cs->state.SetState(CLOSE_WAIT);
                cerr << "State: " << cs->state.GetState() << endl;
                cerr << "Old Last received: " << cs->state.GetLastRecvd() << endl; 
                cs->state.SetLastRecvd(seqnum+1);
                cerr << "New Last received: " << cs->state.GetLastRecvd() << endl;
                
                // Send ACK to FIN request
                Packet p_send;
                build_packet(p_send,*cs,0,ACK);
                MinetSend(mux,p_send);

                // Send FIN to close
                Packet p_send2;
                build_packet(p_send2,*cs,0,FIN);
                MinetSend(mux,p_send2);
                cs->state.SetState(LAST_ACK);
                
              }
              break;
            }
            case LAST_ACK: {
              if(IS_ACK(flag)) {
                cerr << "Received ACK to close" << endl;
                cs->state.SetState(CLOSED);
                clist.erase(cs);
              }
              break;
            }

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
            // passive open 
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


void build_packet(Packet &p, ConnectionToStateMapping<TCPState> &Conn_to_State, int size, flag_state flag_s) {
  IPHeader iph;
  TCPHeader tcph;
  Connection c = Conn_to_State.connection;
  int total_size = size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;

  unsigned char flag = 0;
  switch(flag_s) {
    case SYN: {
      SET_SYN(flag);
      break;
    }
    case SYNACK: {
      SET_SYN(flag);
      SET_ACK(flag);
      break;
    }
    case ACK: {
      SET_ACK(flag);
      break;
    }
    case FIN: {
      SET_FIN(flag);
      SET_ACK(flag);
      break;
    }
    default: {

    }
  }

  iph.SetSourceIP(c.src);
  iph.SetDestIP(c.dest);
  iph.SetProtocol(IP_PROTO_TCP);
  iph.SetTotalLength(total_size);
  p.PushFrontHeader(iph);
  tcph.SetSourcePort(c.srcport, p);
  tcph.SetDestPort(c.destport, p);
  tcph.SetFlags(flag, p);
  Conn_to_State.state.SetLastSent(Conn_to_State.state.GetLastSent()+size);
  tcph.SetSeqNum(Conn_to_State.state.GetLastSent(),p);
  tcph.SetAckNum(Conn_to_State.state.GetLastRecvd(),p);
  tcph.SetWinSize(Conn_to_State.state.GetN(), p);
  tcph.SetHeaderLen(5,p);
  tcph.SetUrgentPtr(0,p);
  tcph.RecomputeChecksum(p);
  p.PushBackHeader(tcph);
  cerr << iph << endl;
  cerr << tcph << endl;
}




