#!/usr/bin/env python3
"""Reproducible synthetic traffic generator. No sockets or external network use."""
import csv, ipaddress, json, struct, pathlib, random
BASE=pathlib.Path(__file__).resolve().parents[1]
MAGIC=b'DNC2'
TYPES={1:'HELLO',2:'CHECKIN',3:'COMMAND',4:'RESULT',5:'KEEPALIVE'}
MAX_PAYLOAD=512
R=random.Random(4106)

def checksum(data):
    if len(data)%2: data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16: total=(total&65535)+(total>>16)
    return (~total)&65535

def msg(typ,session,ordinal,payload=b'',version=1,magic=MAGIC,declared_len=None):
    return struct.pack('!4sBBHHII',magic,version,typ,0,len(payload) if declared_len is None else declared_len,session,ordinal)+payload

class PCAP:
    def __init__(self,name):
        self.name=name;self.frames=[];self.labels=[];self.messages=[];self.frame=0
    def packet(self,t,src,dst,sport,dport,seq,ack,flags,payload=b'',event='background',case='background',ground='benign'):
        self.frame+=1
        srcb=ipaddress.IPv4Address(src).packed;dstb=ipaddress.IPv4Address(dst).packed
        tcp=struct.pack('!HHIIHHHH',sport,dport,seq,ack,(5<<12)|flags,65535,0,0)+payload
        pseudo=srcb+dstb+struct.pack('!BBH',0,6,len(tcp))
        tcpcs=checksum(pseudo+tcp)
        tcp=tcp[:16]+struct.pack('!H',tcpcs)+tcp[18:]
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),self.frame%65535,0x4000,64,6,0,srcb,dstb)
        ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
        mac=b'\x02\x12\x34\x56\x78\x9a'+b'\x02\xaa\xbb\xcc\xdd\xee'+struct.pack('!H',0x0800)
        data=mac+ip+tcp
        secs=int(t);usecs=round((t-secs)*1_000_000)
        self.frames.append((secs,usecs,data))
        self.labels.append((self.frame,f'{t:.3f}',src,dst,sport,dport,event,case,ground,len(payload)))
        return self.frame
    def record(self,case,flow,typ,session,ordinal,valid=True,detail=''):
        self.messages.append((case,flow,TYPES.get(typ,'UNKNOWN'),session,ordinal,valid,detail))
    def save(self):
        f=BASE/'pcap'/self.name
        with f.open('wb') as out:
            out.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
            for sec,usec,pkt in self.frames:
                out.write(struct.pack('<IIII',sec,usec,len(pkt),len(pkt)));out.write(pkt)
        with (BASE/'labels'/self.name.replace('.pcap','-packet-labels.csv')).open('w',newline='') as out:
            w=csv.writer(out);w.writerow(['frame_number','timestamp_seconds','source_ip','destination_ip','source_port','destination_port','event','test_case','ground_truth','tcp_payload_bytes']);w.writerows(self.labels)
        with (BASE/'validation'/self.name.replace('.pcap','-expected-messages.csv')).open('w',newline='') as out:
            w=csv.writer(out);w.writerow(['test_case','flow','message_type','session_id','message_sequence','valid','detail']);w.writerows(self.messages)
        return {'capture':self.name,'frames':len(self.frames),'expected_valid_messages':sum(1 for x in self.messages if x[5]),'expected_rejected_messages':sum(1 for x in self.messages if not x[5])}

class Flow:
    def __init__(self,p,src,dst,sport,dport,t,case,ground):
        self.p=p;self.src=src;self.dst=dst;self.sport=sport;self.dport=dport;self.t=t;self.case=case;self.ground=ground
        self.a=R.randrange(100000,1000000);self.b=R.randrange(100000,1000000)
        for dt,source,dest,sp,dp,seq,ack,flags in [
            (0,src,dst,sport,dport,self.a,0,0x02),
            (0.009,dst,src,dport,sport,self.b,self.a+1,0x12),
            (0.017,src,dst,sport,dport,self.a+1,self.b+1,0x10)]:
            p.packet(t+dt,source,dest,sp,dp,seq,ack,flags,case=case,ground=ground,event='tcp_handshake')
        self.a+=1;self.b+=1;self.t=t+.05
    def send(self,data,delta=.09,reverse=False,event='data'):
        self.t+=delta
        if reverse:
            n=self.p.packet(self.t,self.dst,self.src,self.dport,self.sport,self.b,self.a,0x18,data,event,self.case,self.ground);self.b+=len(data)
        else:
            n=self.p.packet(self.t,self.src,self.dst,self.sport,self.dport,self.a,self.b,0x18,data,event,self.case,self.ground);self.a+=len(data)
        return n
    def close(self):
        self.t+=.08;self.p.packet(self.t,self.src,self.dst,self.sport,self.dport,self.a,self.b,0x11,case=self.case,ground=self.ground,event='tcp_fin')

def standard(p,idx,src,dst,sport,dport,t,case,ground='malicious'):
    f=Flow(p,src,dst,sport,dport,t,case,ground);sid=1000+idx;flow=f'{src}:{sport}->{dst}:{dport}'
    for order,typ in enumerate([1,2,3,4,5],1):
        body=(f'{case}-msg-{order}').encode();payload=msg(typ,sid,order,body)
        f.send(payload,reverse=typ==3);p.record(case,flow,typ,sid,order)
    f.close()

def build(name,variant):
    p=PCAP(name)
    src='10.44.0.10' if variant==1 else ('10.44.0.11' if variant==2 else '10.44.0.20')
    dst='198.51.100.77' if variant==1 else ('203.0.113.117' if variant==2 else '192.0.2.90')
    dport=1177 if variant==1 else 8443
    t=10
    if variant in (1,2):
        for k in range(8): standard(p,k+variant*10,src,dst,40000+k,dport,t+k*3,f'complete_{k+1}')
    else:
        # legitimate application-layer traffic on a shared service port: non-DNC2
        for k in range(8):
            f=Flow(p,src,dst,41000+k,dport,t+k*3,f'ordinary_tls_like_{k}', 'benign')
            f.send(b'\x16\x03\x03\x00\x10'+bytes([k])*16);f.send(b'HTTP/1.1 200 OK\r\n\r\n');f.close()
    start=60
    if variant in (1,2):
        f=Flow(p,src,dst,50001,dport,start,'split_header','malicious')
        raw=msg(2,3001,1,b'abcdefghij')
        for fragment in (raw[:3],raw[3:11],raw[11:]): f.send(fragment,.11)
        p.record('split_header','stream',2,3001,1,detail='3 TCP payload fragments split inside fixed header')
        f.close()
        f=Flow(p,src,dst,50002,dport,start+3,'split_body','malicious');raw=msg(4,3002,1,b'K'*64)
        f.send(raw[:23]);f.send(raw[23:]);p.record('split_body','stream',4,3002,1,detail='payload spans two TCP segments');f.close()
        f=Flow(p,src,dst,50003,dport,start+6,'coalesced','malicious')
        f.send(msg(2,3003,1,b'A')+msg(5,3003,2,b'B')+msg(4,3003,3,b'C'))
        for i,typ in enumerate([2,5,4],1):p.record('coalesced','stream',typ,3003,i,detail='three messages in one TCP segment')
        f.close()
        f=Flow(p,src,dst,50004,dport,start+9,'bad_length','malicious')
        f.send(msg(3,3004,1,b'X',declared_len=4096));p.record('bad_length','stream',3,3004,1,False,'declared payload length exceeds 512');f.close()
        f=Flow(p,src,dst,50005,dport,start+12,'bad_version','malicious')
        f.send(msg(2,3005,1,b'X',version=7));p.record('bad_version','stream',2,3005,1,False,'unsupported protocol version');f.close()
        f=Flow(p,src,dst,50006,dport,start+15,'truncated_message','malicious')
        f.send(msg(2,3006,1,b'XYZ',declared_len=40));p.record('truncated_message','stream',2,3006,1,False,'declares 40 bytes but receives only 3 before FIN');f.close()
        f=Flow(p,src,dst,50007,dport,start+18,'wrong_magic','malicious')
        f.send(msg(2,3007,1,b'wrong',magic=b'FAKE'));p.record('wrong_magic','stream',2,3007,1,False,'invalid magic');f.close()
        f=Flow(p,src,dst,50008,dport,start+21,'unknown_type','malicious')
        f.send(msg(9,3008,1,b'unknown'));p.record('unknown_type','stream',9,3008,1,False,'message type 9 unsupported');f.close()
        f=Flow(p,src,dst,50009,dport,start+24,'server_message','malicious')
        f.send(msg(3,3009,1,b'opaque-command'),reverse=True);p.record('server_message','stream',3,3009,1,detail='server->client message');f.close()
    # benign lookalikes on the same ports and deliberate false-positive traps
    for k in range(8):
        f=Flow(p,'10.44.0.20','192.0.2.90',53000+k,dport,100+k*3,f'benign_lookalike_{k}', 'benign')
        f.send((b'DNC2'+b'\x00'*12) if k%2==0 else b'GET / HTTP/1.1\r\nHost: local.test\r\n\r\n')
        if k%2==0:p.record(f'benign_lookalike_{k}','stream',0,0,0,False,'magic prefix but truncated header')
        f.close()
    return p.save()

if __name__=='__main__':
    results=[build('protocol-malware-scenario-1.pcap',1),build('protocol-malware-scenario-2.pcap',2),build('protocol-benign-reference.pcap',0)]
    (BASE/'validation'/'fixture-summary.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))
