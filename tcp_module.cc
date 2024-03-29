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
                  RST = 5,
                  PSHACK = 6,
                  FINACK = 7 };

void build_packet(Packet &p, ConnectionToStateMapping<TCPState> &Conn_to_State, int size, flag_state flag_s);
void send_data_in_window(ConnectionToStateMapping<TCPState> &Conn_to_State, const MinetHandle &mux, bool GBN, bool timeout);

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

  double Timeout = 1;
  MinetEvent event;

  // List of connection to state mappings 
  ConnectionList<TCPState> clist;
  while (MinetGetNextEvent(event, Timeout)==0) {
    if(event.eventtype==MinetEvent::Timeout) {
      ConnectionList<TCPState>::iterator cs = clist.FindEarliest();
      if(cs != clist.end() && Time() > cs->timeout) {
        cerr << "\n---------------\n";
        cerr << "TIMEOUT" << endl;

        // Switch statement to handle different timeout cases and what to send if it comes up
        switch(cs->state.GetState()) {
          case SYN_RCVD: {
            cs->timeout = Time() + 2;
            Packet p_send;
            build_packet(p_send,*cs,0,SYNACK);
            MinetSend(mux,p_send);
            break;
          }
          case LAST_ACK: {
            cs->timeout = Time() + 2;
            Packet p_send;
            build_packet(p_send,*cs,0,FIN);
            MinetSend(mux,p_send);
            break;
          }
          case SYN_SENT: {
            cs->timeout = Time() + 2;
            Packet p_send;
            build_packet(p_send,*cs,0,SYN);
            MinetSend(mux,p_send);
            break;
          }
          case FIN_WAIT1: {
            cs->timeout = Time() + 2;
            Packet p_send;
            build_packet(p_send,*cs,0,FINACK);
            MinetSend(mux,p_send);
            break;
          }
          case ESTABLISHED: {
            send_data_in_window(*cs,mux,true,true);
            break;
          }
        }

        cerr << "\n---------------\n";
      }
        
    }
    // if we received an unexpected type of event, print error
    else if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
      cerr << "invalid event from Minet" << endl;
    // if we received a valid event from Minet, do processing
    } 
    else {
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

              
              // CS is a pointer to a connection state mapping
              //  Connection to State mapping class:
              //  Connection connection
              //  Time timeout
              //  STATE state
              // bool bTmrActive  

              // Move state to SYN_RCVD
              // Set a timer in case packet is lost
              // Update values
              cs->connection = c;
              cs->timeout = Time() + 2;
              cs->state.SetState(SYN_RCVD);
              cs->state.SetLastRecvd(seqnum+1);
              cs->state.SetLastAcked(cs->state.GetLastSent());
              cs->state.SetLastSent(cs->state.GetLastSent()+1);
              cs->bTmrActive = true;
              
              // Send SYNACK
              Packet p_send;
              build_packet(p_send,*cs,0,SYNACK);
              MinetSend(mux,p_send);
            }
            break;
          }
          case SYN_RCVD: {
            cerr << "Entered SYN_RCVD" << endl;
            if(IS_ACK(flag)) {
              cerr << "Received an ACK" << endl;

              // Move state to ESTABLISHED
              // Turn off timer because received an ACK
              cs->state.SetLastSent(cs->state.GetLastSent() + 1);
              cs->state.SetState(ESTABLISHED);
              cs->state.SetLastAcked(acknum);
              cs->state.SetSendRwnd(win_size);
              cs->bTmrActive = false;

              // Send WRITE response
              cerr << "Passing empty write response to tell application connection is open" << endl;
              SockRequestResponse response;
              response.connection = cs->connection;
              response.type = WRITE;
              response.data = data;
              response.bytes = len;
              response.error = EOK;
              MinetSend(sock,response); 
            }  
            break;
          }
          case SYN_SENT: {
            cerr << "Entered SYN_SENT" << endl;
            if(IS_SYN(flag) && IS_ACK(flag)) {
              cerr << "Received SYNACK" << endl;

              // Received SYNACK so turn off timer and move to state ESTABLISHED
              cs->bTmrActive = false;
              cs->state.SetState(ESTABLISHED);
              cs->state.SetLastSent(cs->state.GetLastSent()+1);
              cs->state.SetLastRecvd(seqnum+1);
              cs->state.SetLastAcked(acknum);
              cs->state.SetSendRwnd(win_size);
              Packet p_send;
              build_packet(p_send,*cs,0,ACK);
              MinetSend(mux,p_send);

              // Send WRITE response
              SockRequestResponse response;
              response.connection = cs->connection;
              response.type = WRITE;
              response.bytes = 0;
              response.error = EOK;
              MinetSend(sock,response);
              cerr << "Sent empty Write response to indicate an established connection" << endl;
            }
            break;
          }
          case ESTABLISHED: {
            cerr << "Entered ESTABLISHED" << endl;

            if(IS_FIN(flag)) {
              cerr << "Close Connection" << endl;
              cs->state.SetState(CLOSE_WAIT);
              cerr << "State: " << cs->state.GetState() << endl;
              cerr << "Old Last received: " << cs->state.GetLastRecvd() << endl; 
              cs->state.SetLastRecvd(seqnum+len+1);
              cerr << "New Last received: " << cs->state.GetLastRecvd() << endl;
              
              // Send ACK to FIN request
              Packet p_send;
              build_packet(p_send,*cs,0,ACK);
              MinetSend(mux,p_send);

              // Send FIN to close
              cs->bTmrActive = true;
              cs->timeout = Time() + 2;
              Packet p_send2;
              build_packet(p_send2,*cs,0,FIN);
              MinetSend(mux,p_send2);
              cs->state.SetState(LAST_ACK);
              
            }
            if(len > 0) {
              cerr << "Received data" << endl;
              cerr << "data:\n" << data << endl;

              cerr << "seqnum: " << seqnum << endl;
              // If correct order packet and checksum is valid then extract data
              if(seqnum == cs->state.GetLastRecvd() && checksum) {
                cerr << "In order Packet" << endl;
                cerr << "Old Last received: " << cs->state.GetLastRecvd() << endl; 
                cs->state.SetLastRecvd(seqnum+len);
                cerr << "New Last received: " << cs->state.GetLastRecvd() << endl;
                cs->state.SetSendRwnd(win_size);

                Packet p_send;
                build_packet(p_send,*cs,0,ACK);
                MinetSend(mux,p_send);

                // Send WRITE response
                cerr << "Passing data up to socket" << endl;
                SockRequestResponse response;
                response.connection = cs->connection;
                response.type = WRITE;
                response.data = data;
                response.bytes = len;
                response.error = EOK;
                MinetSend(sock,response);
                
              }
              else {
                cerr << "Out of order Packet" << endl;
              }

            }
            cerr << "Buffer Size: " << cs->state.SendBuffer.GetSize() << endl;
            if(IS_ACK(flag)) {
              cerr << "Received an ACK" << endl;
              // If new ack then update values and remove from SendBuffer
              if(cs->state.GetLastAcked() < acknum && checksum) {
                if(acknum == cs->state.GetLastSent()) {
                  cs->bTmrActive = false;
                }
                else {
                  cs->timeout = Time() + 2;
                  cs->bTmrActive = true;
                }
                int change_in_ack = acknum - cs->state.GetLastAcked();
                cs->state.last_acked = acknum;
                cerr << "New Last Acked: " << cs->state.GetLastAcked() << endl;

                // Shift the window over to where next expected ACK is
                cs->state.SendBuffer.Erase(0,change_in_ack);
                // Send the next packet if possible
                send_data_in_window(*cs,mux,false,false);

              }
            }
            cerr << "New Buffer Size: " << cs->state.SendBuffer.GetSize() << endl;
            
            break;
          }
          case FIN_WAIT1: {
            cerr << "Entered FIN_WAIT1" << endl;
            if(IS_FIN(flag) && IS_ACK(flag)) {
              cerr << "Received FINACK" << endl;
              // Move to TIME_WAIT
              cs->state.SetState(TIME_WAIT);
              cs->state.SetLastSent(cs->state.GetLastSent()+1);
              cs->state.SetLastRecvd(cs->state.GetLastRecvd()+1);
              Packet p_send;
              build_packet(p_send,*cs,0,ACK);
              MinetSend(mux,p_send);
              cerr << "Sent ACK" << endl;

              // Send CLOSE response
              SockRequestResponse response;
              response.connection = cs->connection;
              response.type = CLOSE;
              response.bytes = 0;
              response.error = EOK;
              MinetSend(sock,response);
              cerr << "Sent CLOSE response" << endl;

              cs->bTmrActive = false;
              cs->state.SetState(CLOSED);
              clist.erase(cs);
              cerr << "Connection Actively Closed" << endl;
            }
            else if(IS_ACK(flag)) {
              cerr << "Received ACK" << endl;
              cs->bTmrActive = false;
              cs->state.SetState(FIN_WAIT2);
              cs->state.SetLastSent(cs->state.GetLastSent()+1);
              cs->state.SetLastRecvd(cs->state.GetLastRecvd()+1);
              cs->state.SetLastAcked(acknum);
            }
            break;
          }
          case FIN_WAIT2: {
            cerr << "Entered FIN_WAIT2" << endl;
            if(IS_FIN(flag)) {
              cerr << "Received FIN" << endl;
              cs->state.SetState(TIME_WAIT);
              Packet p_send;
              build_packet(p_send,*cs,0,ACK);
              MinetSend(mux,p_send);
              cerr << "Sent ACK" << endl;

              // Send CLOSE response
              SockRequestResponse response;
              response.connection = cs->connection;
              response.type = CLOSE;
              response.bytes = 0;
              response.error = EOK;
              MinetSend(sock,response);
              cerr << "Sent CLOSE response" << endl;

              cs->bTmrActive = false;
              cs->state.SetState(CLOSED);
              clist.erase(cs);
              cerr << "Connection Actively Closed" << endl;
            }
            break;
          }
          case LAST_ACK: {
            cerr << "Enetered LAST_ACK" << endl;
            if(IS_ACK(flag)) {
              // Last ACK - close connection
              cerr << "Received ACK to close" << endl;
              cs->bTmrActive = false;
              cs->state.SetState(CLOSED);
              clist.erase(cs);
              cerr << "Connection Passively Closed" << endl;
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
        ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
        switch(s.type) {
          case CONNECT: {
            // active open 
            cerr << "CONNECT request" << endl;
            TCPState new_state(rand(),SYN_SENT,3);
            ConnectionToStateMapping<TCPState> Conn_to_State(s.connection,Time()+2,new_state,true);
            Conn_to_State.state.SetLastAcked(0);
            clist.push_back(Conn_to_State);
            Packet p_send;
            build_packet(p_send,Conn_to_State,0,SYN);
            MinetSend(mux,p_send);

            // Send STATUS response
            response.connection = s.connection;
            response.type = STATUS;
            response.bytes = 0;
            response.error = EOK;
            MinetSend(sock,response);
            break;
          }
          case ACCEPT: {
            // passive open 
            cerr << "ACCEPT request" << endl;

            // Add connection state pair to connections list
            TCPState new_state(rand(),LISTEN,3);
            ConnectionToStateMapping<TCPState> Conn_to_State(s.connection,Time(),new_state,false);
            cerr << "New connection: " << Conn_to_State << endl;
            clist.push_back(Conn_to_State);

            // Send STATUS response
            response.connection = s.connection;
            response.type = STATUS;
            response.bytes = 0;
            response.error = EOK;
            MinetSend(sock,response);
            cerr << "Sent STATUS response" << endl; 

            break;
          }
          case WRITE: {
            cerr << "WRITE request" << endl;
            unsigned int size = 0;
            int err = ENOMATCH;
            // If theres a matching connection add data to sending buffer
            if(cs != clist.end() && cs->state.GetState() == ESTABLISHED) {
              Buffer b = s.data;
              cerr << b << endl;
              cs->state.SendBuffer.AddBack(b);
              size = b.GetSize();
              cerr << "Size: " << size << endl;
              // Send all possible data according to N (size of window)
              send_data_in_window(*cs,mux,true,false);
              err = EOK;
            }
            // Send STATUS response
            response.connection = s.connection;
            response.type = STATUS;
            response.bytes = size;
            response.error = err;
            MinetSend(sock,response);
            cerr << "Sent STATUS response" << endl;  
            break;
          }
          case CLOSE: {
            cerr << "CLOSE request" << endl;
            int err = ENOMATCH;
            // Close if in connections
            if(cs != clist.end() && cs->state.GetState() == ESTABLISHED) {
              cs->state.SetState(FIN_WAIT1);
              cs->bTmrActive = true;
              cs->timeout = Time() + 2;
              Packet p_send;
              build_packet(p_send,*cs,0,FINACK);
              MinetSend(mux,p_send);
              err = EOK;
            }

            // Send STATUS response
            response.connection = s.connection;
            response.type = STATUS;
            response.bytes = 0;
            response.error = err;
            MinetSend(sock,response);
            cerr << "Sent STATUS response" << endl; 
            break;
          }
          case FORWARD: {
            // Send STATUS response
            response.connection = s.connection;
            response.type = STATUS;
            response.bytes = 0;
            response.error = EOK;
            MinetSend(sock,response);
            cerr << "Sent STATUS response" << endl; 
            break;
          }
          case STATUS: 
          default: {

            break;
          }

        }
        cerr << "---------------\n";
      }
    }
  }
  MinetDeinit();
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
    case FINACK: {
      SET_FIN(flag);
      SET_ACK(flag);
      break;
    }
    case PSHACK: {
      SET_PSH(flag);
      SET_ACK(flag);
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
  tcph.SetSeqNum(Conn_to_State.state.GetLastSent(),p);
  Conn_to_State.state.SetLastSent(Conn_to_State.state.GetLastSent()+size);
  tcph.SetAckNum(Conn_to_State.state.GetLastRecvd(),p);
  tcph.SetWinSize(Conn_to_State.state.GetN(), p);
  tcph.SetHeaderLen(5,p);
  tcph.SetUrgentPtr(0,p);
  tcph.RecomputeChecksum(p);
  p.PushBackHeader(tcph);
  cerr << iph << endl;
  cerr << tcph << endl;
}

void send_data_in_window(ConnectionToStateMapping<TCPState> &Conn_to_State, const MinetHandle &mux, bool GBN, bool timeout) {
  
  // If it is a timeout then move the nextseqnum to equal the last acked we got
  if(timeout) {
    Conn_to_State.state.SetLastSent(Conn_to_State.state.GetLastAcked());
  }

  unsigned int packet_size = 0;
  unsigned int already_sent_no_acks = Conn_to_State.state.GetLastSent() - Conn_to_State.state.GetLastAcked();
  unsigned int n = Conn_to_State.state.GetN();
  unsigned int ready_to_send = n - already_sent_no_acks;
  unsigned int bytes_sent = 0;
  unsigned int size = Conn_to_State.state.SendBuffer.GetSize();
  unsigned int count = 0;
  Buffer send_buf;

  // If we do not want to send from beginning of window then start after already acked packets
  if(!GBN) {
    bytes_sent = already_sent_no_acks;
  }

  cerr << "New size of Buffer: " << size << endl;
  cerr << "Last Sent: " << Conn_to_State.state.GetLastSent() << endl;
  cerr << "Bytes able to send: " << ready_to_send << endl;
  cerr << "Sending all possible packets in window" << endl;

  // While the bytes we have sent is less than the size of the buffer and how many we can send based on N
  while(bytes_sent < size && bytes_sent < ready_to_send) {
    // Set timer once first packet is made
    if(count == 0) {
      Conn_to_State.timeout = Time() + 2;
      Conn_to_State.bTmrActive = true;
    }
    // Packet size is either how much is left or how much we can possibly fit
    packet_size = std::min(size-bytes_sent,TCP_MAXIMUM_SEGMENT_SIZE);
    char data_send[packet_size+1];
    Conn_to_State.state.SendBuffer.GetData(data_send,packet_size,bytes_sent);
    send_buf.SetData(data_send,packet_size,0);

    // Create packet with buffer data in it adn send to mux
    Packet *p_send = new Packet(send_buf);
    build_packet(*p_send,Conn_to_State,packet_size,PSHACK);
    MinetSend(mux,*p_send);
    delete p_send;

    cerr << "Packet Sent" << endl;
    cerr << "New Buffer Size: " << Conn_to_State.state.SendBuffer.GetSize() << endl;
    bytes_sent+=packet_size;
    count++;
  }

}















