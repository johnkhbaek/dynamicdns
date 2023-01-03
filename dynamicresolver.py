# by exploitpreacher
# copied from zoneresolver.py by dnslib
from __future__ import print_function
import copy
from dnslib import RR,QTYPE,RCODE
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
class DynamicResolver(BaseResolver):
    def __init__(self,zone=False):
        # add zone if supplied
        self.zone = []
        if zone:
            for rr in RR.fromZone(zone):
                if not self.exist(rr):
                    self.add_record(rr) 

    def exist(self,record):
        for name,rtype,rr in self.zone:
            if getattr(record.rname,'__eq__')(name) and rtype == QTYPE[record.rtype]:
                return True
        return False

    def add_record(self,rr):
        self.zone.append((rr.rname,QTYPE[rr.rtype],rr))

    def del_record(self,rr):
        self.zone.remove((rr.rname,QTYPE[rr.rtype],rr))

    def print_zone(self):
        # index #2 contains the zone record
        for name,rtype,rr in self.zone:
            print("%s" % rr.toZone())

    def resolve(self,request,handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        print("[DEBUG] in resolve qname:%s | qtype:%s" %(qname,qtype))
        
        for name,rtype,rr in self.zone:
            # Check if label & type match
            if getattr(qname,'__eq__')(name) and (qtype == rtype or 
                                                 qtype == 'ANY' or 
                                                 rtype == 'CNAME'):
                reply.add_answer(rr)
                # Check for A/AAAA records associated with reply and
                # add in additional section
                if rtype in ['CNAME','NS','MX','PTR']:
                    for a_name,a_rtype,a_rr in self.zone:
                        if a_name == rr.rdata.label and a_rtype in ['A','AAAA']:
                            reply.add_ar(a_rr)
        if not reply.rr:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

#-------------------------------------------------------------
if __name__ == '__main__':
    import argparse,sys,time

    p = argparse.ArgumentParser(description="Zone DNS Resolver")
#    p.add_argument("--zone","-z",required=True,
    p.add_argument("--zone","-z",
                        metavar="<zone-file>",
                        help="Zone file ('-' for stdin)")
    p.add_argument("--port","-p",type=int,default=53,
                        metavar="<port>",
                        help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                        metavar="<address>",
                        help="Listen address (default:all)")
    p.add_argument("--tcp",action='store_true',default=False,
                        help="TCP server (default: UDP only)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    args = p.parse_args()
    
    if args.zone == '-':
        args.zone = sys.stdin
    elif args.zone:
        args.zone = open(args.zone)
    else:
        print("no zones given in the args")

    resolver = DynamicResolver(args.zone)
    logger = DNSLogger(args.log,True)

    print("Starting Zone Resolver (%s:%d) [%s]" % (
                        args.address or "*",
                        args.port,
                        "UDP/TCP" if args.tcp else "UDP"))
    resolver.print_zone()

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger)
        tcp_server.start_thread()

    while udp_server.isAlive():
        userinput = input("DNS> ")
        if userinput:
            # tokenize the command
            tokens = userinput.split()
            command = tokens[0]
            if len(tokens):
                args = ' '.join(tokens[1:])
            else:
                args = ''
            if command in ['help','h']:
                print("you need help?")
            elif command in ['die','exit','quit']:
                print("bye bye!")
                exit()
            elif command in ['print']:
                resolver.print_zone()
            elif command in ['add']:
                for rr in RR.fromZone(args):
                    resolver.add_record(rr)
            elif command in ['del']:
                for rr in RR.fromZone(args):
                    resolver.del_record(rr)
            else:
                print("Unrecognized command %s, args %s" % (command,args))
