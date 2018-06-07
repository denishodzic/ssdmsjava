package testing;

import org.xbill.DNS.*;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.List;

public class TestingResolver {

    public static final int DEFAULT_PORT = 53;
    public static final int DEFAULT_EDNS_PAYLOADSIZE = 1280;
    private InetSocketAddress address;
    private InetSocketAddress localAddress;
    private boolean useTCP;
    private boolean ignoreTruncation;
    private OPTRecord queryOPT;
    private TSIG tsig;
    private long timeoutValue;
    private static final short DEFAULT_UDPSIZE = 512;
    private static String defaultResolver = "localhost";
    private static int uniqueID = 0;

    public TestingResolver(String hostname) throws UnknownHostException {
        this.timeoutValue = 10000L;
        if (hostname == null) {
            hostname = ResolverConfig.getCurrentConfig().server();
            if (hostname == null) {
                hostname = defaultResolver;
            }
        }

        InetAddress addr;
        if (hostname.equals("0")) {
            addr = InetAddress.getLocalHost();
        } else {
            addr = InetAddress.getByName(hostname);
        }

        this.address = new InetSocketAddress(addr, 53);
    }

    public TestingResolver() throws UnknownHostException {
        this((String) null);
    }

    public InetSocketAddress getAddress() {
        return this.address;
    }

    public static void setDefaultResolver(String hostname) {
        defaultResolver = hostname;
    }

    public void setPort(int port) {
        this.address = new InetSocketAddress(this.address.getAddress(), port);
    }

    public void setAddress(InetSocketAddress addr) {
        this.address = addr;
    }

    public void setAddress(InetAddress addr) {
        this.address = new InetSocketAddress(addr, this.address.getPort());
    }

    public void setLocalAddress(InetSocketAddress addr) {
        this.localAddress = addr;
    }

    public void setLocalAddress(InetAddress addr) {
        this.localAddress = new InetSocketAddress(addr, 0);
    }

    public void setTCP(boolean flag) {
        this.useTCP = flag;
    }

    public void setIgnoreTruncation(boolean flag) {
        this.ignoreTruncation = flag;
    }

    public void setEDNS(int level, int payloadSize, int flags, List options) {
        if (level != 0 && level != -1) {
            throw new IllegalArgumentException("invalid EDNS level - must be 0 or -1");
        } else {
            if (payloadSize == 0) {
                payloadSize = 1280;
            }

            this.queryOPT = new OPTRecord(payloadSize, 0, level, flags, options);
        }
    }

    public void setEDNS(int level) {
        this.setEDNS(level, 0, 0, (List) null);
    }

    public void setTSIGKey(TSIG key) {
        this.tsig = key;
    }

    TSIG getTSIGKey() {
        return this.tsig;
    }

    public void setTimeout(int secs, int msecs) {
        this.timeoutValue = (long) secs * 1000L + (long) msecs;
    }

    public void setTimeout(int secs) {
        this.setTimeout(secs, 0);
    }

    long getTimeout() {
        return this.timeoutValue;
    }

    private Message parseMessage(byte[] b) throws WireParseException {
        try {
            return new Message(b);
        } catch (IOException var3) {
            IOException e = var3;
            if (Options.check("verbose")) {
                var3.printStackTrace();
            }

            if (!(var3 instanceof WireParseException)) {
                e = new WireParseException("Error parsing message");
            }

            throw (WireParseException) e;
        }
    }

    private void verifyTSIG(Message query, Message response, byte[] b, TSIG tsig) {
        if (tsig != null) {
            int error = tsig.verify(response, b, query.getTSIG());
            if (Options.check("verbose")) {
                System.err.println("TSIG verify: " + Rcode.TSIGstring(error));
            }

        }
    }

    private void applyEDNS(Message query) {
        if (this.queryOPT != null && query.getOPT() == null) {
            query.addRecord(this.queryOPT, 3);
        }
    }

    private int maxUDPSize(Message query) {
        OPTRecord opt = query.getOPT();
        return opt == null ? 512 : opt.getPayloadSize();
    }

    public Message send(Message query, int type, String hostname) throws IOException {

        // Answer weberdns.de on response DNSSEC Type 1
        Reader  a = new FileReader("src/testing/dnssecresponse/weber.txt");
        Message b = readMessage(a);

        // Answer weberdns.de on response DNSKEY Type 48

        Reader  c = new FileReader("src/testing/dnssecresponse/weberdnskey.txt");
        Message d = readMessage(c);

        // Answer weberdns.de on response DNSSEC MX DNS Type 1

        Reader  e = new FileReader("src/testing/dnssecresponse/webermxdns1.txt");
        Message f = readMessage(e);

        // Answer weberdns.de on response DNSKEY MX DNS Type 48

        Reader  g = new FileReader("src/testing/dnssecresponse/webermxdns48.txt");
        Message h = readMessage(g);

        // Answer weberdns.de TLSA response Port 25 Type 52

        Reader  i = new FileReader("src/testing/tlsaresponse/tlsa.txt");
        Message j = readMessage(i);

        // Answer weberdns.de TLSA response Port 465 Type 52

        Reader  k = new FileReader("src/testing/tlsaresponse/tlsa465.txt");
        Message l = readMessage(k);

        // Answer weberdns.de TLSA response Port 587 Type 52

        Reader  m = new FileReader("src/testing/tlsaresponse/tlsa587.txt");
        Message n = readMessage(m);

        // Answer weberdns.de TLSA response Port 25 Type 52

        Reader  o = new FileReader("src/testing/tlsaresponse/tlsa443.txt");
        Message p = readMessage(o);

        // Answer weberdns.de CAA response Type 257

        Reader  q = new FileReader("src/testing/caaresponse/caa.txt");
        Message r = readMessage(q);


        query = (Message) query.clone();
        this.applyEDNS(query);
        if (this.tsig != null) {
            this.tsig.apply(query, (TSIGRecord) null);
        }

        byte[] out = query.toWire(65535);
        int udpSize = this.maxUDPSize(query);
        boolean tcp = false;
        long endTime = System.currentTimeMillis() + this.timeoutValue;

        if (type < 0) {
            return null;
        } else {
            switch (type) {
                case 1:
                    if(!hostname.contains("mail.weberdns.de.")){
                        return b;
                    }
                    else{
                        return f;
                    }
                case 48:
                    if(!hostname.contains("mail.weberdns.de.")){
                        return d;
                    }
                    else{
                        return h;
                    }
                case 257:
                    return r;
                case 52:
                    if(hostname.contains("_25._tcp.mail.weberdns.de.")){
                        return j;
                    }
                    else if(hostname.contains("_465._tcp.mail.weberdns.de.")){
                        return l;
                    }
                    else if(hostname.contains("_587._tcp.mail.weberdns.de.")){
                        return n;
                    }
                    else{
                        return p;
                    }
            }
        }
        return null;
    }

        public Object sendAsync(Message query, ResolverListener listener) {
            Integer id;
            synchronized(this) {
                id = new Integer(uniqueID++);
            }

            Record question = query.getQuestion();
            String qname;
            if (question != null) {
                qname = question.getName().toString();
            } else {
                qname = "(none)";
            }

            String name = this.getClass() + ": " + qname;
            return id;
        }

        private Message sendAXFR(Message query) throws IOException {
            Name qname = query.getQuestion().getName();
            ZoneTransferIn xfrin = ZoneTransferIn.newAXFR(qname, this.address, this.tsig);
            xfrin.setTimeout((int)(this.getTimeout() / 1000L));
            xfrin.setLocalAddress(this.localAddress);

            try {
                xfrin.run();
            } catch (ZoneTransferException var7) {
                throw new WireParseException(var7.getMessage());
            }

            List records = xfrin.getAXFR();
            Message response = new Message(query.getHeader().getID());
            response.getHeader().setFlag(5);
            response.getHeader().setFlag(0);
            response.addRecord(query.getQuestion(), 0);
            Iterator it = records.iterator();

            while(it.hasNext()) {
                response.addRecord((Record)it.next(), 1);
            }

            return response;
        }

        public Message readMessage(Reader in) throws IOException {
            BufferedReader r;
            if (in instanceof BufferedReader) {
                r = (BufferedReader)in;
            }
            else {
                r = new BufferedReader(in);
            }

            Message m = null;
            String line = null;
            int section = 103;
            while ((line = r.readLine()) != null) {
                String[] data;
                if (line.startsWith(";; ->>HEADER<<- ")) {
                    section = 101;
                    m = new Message();
                }
                else if (line.startsWith(";; QUESTIONS:")) {
                    section = 102;
                }
                else if (line.startsWith(";; ANSWERS:")) {
                    section = Section.ANSWER;
                    line = r.readLine();
                }
                else if (line.startsWith(";; AUTHORITY RECORDS:")) {
                   section = Section.AUTHORITY;
                   line = r.readLine();
                }
                else if (line.startsWith(";; ADDITIONAL RECORDS:")) {
                    section = 100;
                }
                else if (line.startsWith("####")) {
                    return m;
                }
                else if (line.startsWith("#")) {
                    continue;
                }

                switch (section) {
                    case 100: // ignore
                        break;

                   case 101: // header
                       section = 100;
                       data = line.substring(";; ->>HEADER<<- ".length()).split(",");
                       m.getHeader().setRcode(Rcode.value(data[1].split(":\\s*")[1]));
                       m.getHeader().setID(Integer.parseInt(data[2].split(":\\s*")[1]));
                       break;

                    case 102: // question
                        line = r.readLine();
                        data = line.split(",");
                       Record q = Record.newRecord(
                               Name.fromString(data[0].replaceAll(";;\\s*", "")),
                               Type.value(data[1].split("\\s*=\\s*")[1]),
                               DClass.value(data[2].split("\\s*=\\s*")[1]));
                        m.addRecord(q, Section.QUESTION);
                        section = 100;
                        break;

                        default:
                            if (line != null && !"".equals(line)) {
                                Master ma = new Master(new ByteArrayInputStream(line.getBytes()));
                                Record record = ma.nextRecord();
                                if (record != null) {
                                    m.addRecord(record, section);
                                }
                            }
                }
            }

            r.close();
            return m;
    }
}
