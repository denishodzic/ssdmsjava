package securitycheck;

import org.xbill.DNS.*;

import java.io.IOException;

public class CAARecord {

    static Name name = null;
    static int type = 1;
    static int dclass = 1;

    public static void main(String[] args) throws IOException, DNSSEC.DNSSECException {
        disableWarning();
        String hostname = "weberdns.de"; //bonuscard, mail.de, sasis.ch, bonus-services-test.ch, hin.ch, prisma-world.com, securitymonitoring.ch
        System.out.println("-------------------------------------------------------" +hostname+ "-------------------------------------------------------");
        checkCAARecord(hostname);
    }
    //fingerprint hashes
    //mailserver

    private static void checkCAARecord(String hostname) throws IOException, DNSSEC.DNSSECException {
        SimpleResolver res = new SimpleResolver();
        //TestingResolver res = new TestingResolver();
        name = Name.fromString(hostname, Name.root);
        type = 257;
        dclass = 1;
        Record caaKey = Record.newRecord(name, type, dclass);
        Message queryCAA = Message.newQuery(caaKey);
        Message responseCAA = res.send(queryCAA);
        //Message responseCAA = res.send(queryCAA,type, hostname);
        System.out.println("-------------------------------------------------------CAA Query-------------------------------------------------------");
        printSections(responseCAA);
    }

    private static void printSections(Message message){
        Record[] sect1 = message.getSectionArray(1);if(null != sect1 && 0 <= sect1.length){
            for(int i = 0; i < sect1.length; i++){
                Record r = sect1[i];
                if(r instanceof org.xbill.DNS.CAARecord) {
                    System.out.println("CAARECORD    " + i);
                    org.xbill.DNS.CAARecord dr = (org.xbill.DNS.CAARecord) r;
                    System.out.println(i + "   Flag:  " + dr.getFlags() + "   :   Flag 0 is currently used to represent the critical flag, which isn't in use anymore.");
                    System.out.print(i + "   Tag:  " + dr.getTag());
                    String tag = dr.getTag();
                    checkTag(tag);
                    System.out.println(i + "   Value:  " + dr.getValue() + "   :   The value associated with the tag.");
                }
            }
        }
        else{
            System.out.println("no records !");
        }
    }

    private static void checkTag(String tag) {
        switch(tag){
            case "issue":
                System.out.println("   :   explicity authorizes a single certificate authority to issue a certificate (any type) for the hostname.");
                break;
            case "issuewild":
                System.out.println("   :   explicity authorizes a single certificate authority to issue a wildcard certificate (and only wildcard) for the hostname.");
                break;
            case "iodef":
                System.out.println("   :   specifies an URL to which a certificate authority may report policy violations.");
                break;
        }
    }

    public static void disableWarning() {
        System.err.close();
        System.setErr(System.out);
    }
}

