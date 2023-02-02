import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import jpbc.extend.pairing.PairingFactory;
//import smu.smc.lsss.LSSSEngine;
//import smu.smc.lsss.LSSSMatrix;

public class RABETest {
    public static RABEMSK msk;
    public static RABEMPK mpk;
    public static RevokeList rl;
    public static KUNodes st;

    public static RABEUSK[] usk;
    public static RABEUpdateK ku;
    public static RABEDK[] dk;

    public static RABEKeyGen kgen;
    public static RABEEngine rabe;

    public static int user_count = 2;
    public static int user_total_count = 8;
    public static int[] revoked_uids = new int[]{0};
    //public static int attr_len = 35;
    public static long t = 100;

    public static Element m;
    public static String[] attrs;
    public static String policy;
    public static LSSSMatrix policy_t;
    public static RABECipher[] c;

    public static void test_setup(){
        PairingParametersGenerator pg = new TypeACurveGenerator(160, 512);
        PairingParameters param = pg.generate();
        Pairing pairing = PairingFactory.getPairing(param);

        kgen = new RABEKeyGen();
        kgen.setup(user_total_count, pairing);

        msk = kgen.getMsk();
        mpk = kgen.getMpk();
        st = kgen.getSt();
        rl = kgen.getRl();
    }

    public static void test_kgen(int attr_len){

        attrs = new String[attr_len];
        for (int i = 0; i < attrs.length; i++) {
            attrs[i] = "Attr" + i;
        }

        usk = new RABEUSK[user_count];
        for (int i = 0; i < user_count; i++) {
            usk[i] = kgen.kgen(i, attrs);
        }
    }

    public static void test_kupdate(){
        for (int i = 0; i < revoked_uids.length; i++) {
            rl.add(revoked_uids[i], 50 + i);
        }

        ku = kgen.kupdate(t);
    }

    public static void test_dkgen(){
        dk = new RABEDK[user_count];
        for (int i = 0; i < user_count; i++) {
            dk[i] = kgen.dkgen(usk[i], ku);
        }
    }

    public static void test_enc(int attr_len){
        rabe = new RABEEngine(mpk, msk);
        m = mpk.getPairing().getGT().newRandomElement().getImmutable();

        policy = "";
        for (int i = 0; i < attr_len - 1; i++) {
            policy += attrs[i] + " & ";
        }
        policy += attrs[attr_len - 1];
        LSSSEngine lsssEngine = new LSSSEngine();
        policy_t = lsssEngine.genMatrix(policy, mpk.getPairing().getZr());

        c = new RABECipher[user_count];
        for (int i = 0; i < user_count; i++) {
            c[i] = rabe.enc(m, policy_t, t);
        }
    }

    public static void test_dec(){
        Element rm;

        for (int i = 0; i < user_count; i++) {
            if(dk[i] == null){
                //System.out.println("can not decrypt for user " + i + "!");
                continue;
            }
            rm = rabe.decrypt(dk[i], c[i]);
            //System.out.println(rm);
            //System.out.println(m);
            if(m.isEqual(rm)){
                System.out.println("decrypt successfully for user " + i + "!");
            }
//            else{
//                System.out.println("decrypt failed for user " + i + "!");
//            }
        }
    }

    public static void main(String[] args){
        int loop = 1;
        long startTime,endTime;
        //int attr_len = 60;
        for (int attr_len=10; attr_len <= 60; attr_len += 5) {
            System.out.println("attr_len = " + attr_len);
            startTime = System.currentTimeMillis();
            for (int i = 0; i < loop; i++) {
                test_setup();
            }
            endTime = System.currentTimeMillis();
            System.out.println("setup " + (endTime - startTime) / loop + "ms");

            System.out.println("Finish setup");

            startTime = System.currentTimeMillis();
            //for (int i = 0; i < loop; i++) {
            test_kgen(attr_len);
            //}
            endTime = System.currentTimeMillis();
            System.out.println("kgen " + (endTime - startTime) + "ms");

            System.out.println("Finish kgen");
            startTime = System.currentTimeMillis();
            //for (int i = 0; i < loop; i++) {
            test_kupdate();
            //}
            endTime = System.currentTimeMillis();
            System.out.println("kupdate " + (endTime - startTime) + "ms");

            System.out.println("Finish kupdate");
            startTime = System.currentTimeMillis();
            //for (int i = 0; i < loop; i++) {
            test_dkgen();
            //}
            endTime = System.currentTimeMillis();
            System.out.println("dkgen " + (endTime - startTime) + "ms");
            //test_dkgen();

            System.out.println("Finish dkgen");
            startTime = System.currentTimeMillis();
            //for (int i = 0; i < loop; i++) {
            test_enc(attr_len);
            //}
            endTime = System.currentTimeMillis();
            System.out.println("enc " + (endTime - startTime) + "ms");

            System.out.println("Finish enc");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < loop; i++) {
                test_dec();
            }
            endTime = System.currentTimeMillis();
            System.out.println("dec " + (endTime - startTime) / loop + "ms");

            System.out.println("Finish dec");
        }
//        test_setup();
//        System.out.println("Finish setup");
//        test_kgen();
//        System.out.println("Finish kgen");
//        test_kupdate();
//        System.out.println("Finish kupdate");
//        test_dkgen();
//        System.out.println("Finish dkgen");
//        test_enc();
//        System.out.println("Finish enc");
//        test_dec();
//        System.out.println("Finish dec");
    }
}
