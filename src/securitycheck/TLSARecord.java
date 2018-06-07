package securitycheck;

import org.xbill.DNS.*;

import java.io.IOException;

public class TLSARecord {
    static Name name = null;
    static int type = 1;
    static int dclass = 1;

    // hash vergliechen mitem effektive
    public static void main(String[] args) throws IOException, DNSSEC.DNSSECException {
        disableWarning();
        String hostname = "weberdns.de"; //TLSA Record //_25._tcp. isi.edu/johnhpapers _443._tcp.www.huque.com.   mail.de
        System.out.println("=========================================================================================================================");
        System.out.println("======================================================   " + hostname + "   ======================================================");
        System.out.println("=========================================================================================================================");
        convertToMXRecord(hostname);
        checkTLSAFQDN(hostname);
    }

    private static void checkTLSA(String hostname) throws IOException, DNSSEC.DNSSECException {
        SimpleResolver res = new SimpleResolver();
        //TestingResolver res = new TestingResolver();
        String nameString = hostname;
        name = Name.fromString(nameString, Name.root);
        type = 52;
        dclass = 1;
        Record tlsa = Record.newRecord(name, type, dclass);
        Message querytlsa = Message.newQuery(tlsa);
        Message responsetlsa = res.send(querytlsa);
        //Message responsetlsa = res.send(querytlsa, type, hostname);
        System.out.println("-------------------------------------------------------TLSA Query-------------------------------------------------------");
        System.out.println();
        printSections(responsetlsa);
    }

    private static void printSections(Message message) throws DNSSEC.DNSSECException {
        Record[] sect1 = message.getSectionArray(1);
        if (null != sect1 && 0 <= sect1.length) {
            for (int i = 0; i < sect1.length; i++) {
                Record r = sect1[i];
                if (r instanceof org.xbill.DNS.TLSARecord) {
                    System.out.println("TLSARECORD    " + i);
                    org.xbill.DNS.TLSARecord dr = (org.xbill.DNS.TLSARecord) r;
                    System.out.print(i + "   CertificateUsage : " + dr.getCertificateUsage());
                    int certificateUsage = dr.getCertificateUsage();
                    checkUsage(certificateUsage);
                    System.out.print(i + "   Matching Type : " + dr.getMatchingType());
                    int matchingType = dr.getMatchingType();
                    checkType(matchingType);
                    System.out.print(i + "   Selector : " + dr.getSelector());
                    int selector = dr.getSelector();
                    checkSelector(selector);
                    System.out.println(i + "   Name : " + dr.getName());
                    System.out.println(i + "   TLSA Data : " + dr.rdataToString());
                }
            }
        }
    }

    private static void checkSelector(int selector) {
        switch (selector) {
            case 0:
                System.out.println("   :   The hash contains the complete certificate (not recommended). ");
                break;
            case 1:
                System.out.println("   :   The hash contains a SHA-256 hash.");
                break;
            case 2:
                System.out.println("   :   The hash contains a SHA-512 hash.");
                break;
        }
    }

    private static void checkType(int matchingType) {
        switch (matchingType) {
            case 0:
                System.out.println("   :   A hash is created from the complete certificate. ");
                break;
            case 1:
                System.out.println("   :   Only a hash of the public key and the algorithm is created.");
                break;
        }
    }

    private static void checkUsage(int certificateUsage) {
        switch (certificateUsage) {
            case 0:
                System.out.println("   :   The hash belongs to the certification authority that can issue certificates for this host. The client must know the certification authority or it must be signed by a trusted certification authority.  ");
                break;
            case 1:
                System.out.println("   :   The hash belongs to the server certificate. It must be signed by a certification authority trusted by the client.  ");
                break;
            case 2:
                System.out.println("   :   The hash belongs to a certification authority that can issue certificates for this host. The client should have your trust even if it is unknown to him and not signed by any known certification authority.  ");
                break;
            case 3:
                System.out.println("   :   The hash belongs to the server certificate and the client should trust it without further checking the trust chain.  ");
                break;
        }
    }

    public static void convertToMXRecord (String hostname) throws IOException, DNSSEC.DNSSECException {
        Record[] records = new Lookup(hostname, Type.MX).run();
        for (int i = 0; i < records.length; i++) {
            MXRecord mx = (MXRecord) records[i];
            System.out.println(i + ":  ***********" +"      Host " + mx.getTarget() + " has preference " + mx.getPriority() + " **************");
            String tslaString = mx.getTarget().toString();
            setPort(tslaString);
        }
    }

    private static void setPort(String tslaString) throws IOException, DNSSEC.DNSSECException {
        String target25 = "_25._tcp.";
        target25 += tslaString;
        System.out.println("==================================== MX RECORDS TLSA CHECK SMTP PORT 25 PROTOCOL TCP ====================================");
        System.out.println();
        checkTLSA(target25);
        String target465 = "_465._tcp.";
        target465 += tslaString;
        System.out.println("==================================== MX RECORDS TLSA CHECK SMTP PORT 465 PROTOCOL TCP ===================================");
        System.out.println();
        checkTLSA(target465);
        String target587 = "_587._tcp.";
        target587 += tslaString;
        System.out.println("==================================== MX RECORDS TLSA CHECK SMTP PORT 587 PROTOCOL TCP ===================================");
        System.out.println();
        checkTLSA(target587);
    }

    public static void checkTLSAFQDN (String hostname) throws IOException, DNSSEC.DNSSECException {
        String target = "_443._tcp.";
        target += hostname;
        System.out.println("==================================== FQDN TLSA CHECK HTTPS PORT 443 PROTOCOL TCP ========================================");
        System.out.println();
        checkTLSA(target);
    }

    public static void disableWarning(){
        System.err.close();
        System.setErr(System.out);
    }
}

