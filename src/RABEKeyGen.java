import it.unisa.dia.gas.jpbc.*;
//import smu.smc.dcph.Utils;

import java.util.*;

public class RABEKeyGen {
    private RABEMSK msk;
    private RABEMPK mpk;
    private RevokeList rl;
    private KUNodes st;


    public void setup(int num, Pairing pairing){
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element h = pairing.getG2().newRandomElement().getImmutable();
        Element e = pairing.pairing(g, h).getImmutable();

        Element a1 = pairing.getZr().newRandomElement();
        Element a2 = pairing.getZr().newRandomElement();
        Element b1 = pairing.getZr().newRandomElement();
        Element b2 = pairing.getZr().newRandomElement();
        Element d1 = pairing.getZr().newRandomElement();
        Element d2 = pairing.getZr().newRandomElement();
        Element d3 = pairing.getZr().newRandomElement();

        // H1 = h ^ a1
        Element H1 = h.powZn(a1).getImmutable();
        // H2 = h ^ a2
        Element H2 = h.powZn(a2).getImmutable();
        // T1 = e(g, h) ^ (d1*a1 + d3)
        Element T1 = e.powZn(d1.duplicate().mul(a1).add(d3)).getImmutable();
        // T2 = e(g, h) ^ (d2*a2 + d3)
        Element T2 = e.powZn(d2.duplicate().mul(a2).add(d3)).getImmutable();

        Element g_d1 = g.powZn(d1).getImmutable();
        Element g_d2 = g.powZn(d2).getImmutable();
        Element g_d3 = g.powZn(d3).getImmutable();
        this.mpk = new RABEMPK(pairing, H1, H2, T1, T2);
        this.msk = new RABEMSK(g, h,
                a1.getImmutable(), a2.getImmutable(),
                b1.getImmutable(), b2.getImmutable(),
                g_d1, g_d2, g_d3);
        this.st = KUNodes.newInstance(num, pairing.getG1());
        this.rl = new RevokeList();
        return;
    }

    public RABEUSK kgen(int id, String[] attrs){
        Field zr = this.mpk.getPairing().getZr();
        Field g1 = this.mpk.getPairing().getG1();

        Element r1 = zr.newRandomElement();
        Element r2 = zr.newRandomElement();

        Element b1 = this.msk.getB1();
        Element b2 = this.msk.getB2();
        Element[] ainvs = new Element[]{
                this.msk.getA1(), this.msk.getA2()
        };
        Element[] g_dz = new Element[]{
                this.msk.getG_d1(),
                this.msk.getG_d2(),
                this.msk.getG_d3()
        };
        Element g = this.msk.getG();
        Element h = this.msk.getH();

        Element[] tmp = new Element[3];
        tmp[0] = b1.mul(r1);
        tmp[1] = b2.mul(r2);
        tmp[2] = r1.duplicate().add(r2);

        Element[] sk0 = new Element[3];
        for (int k = 0; k < 3; k++) {
            sk0[k] = h.powZn(tmp[k]).getImmutable();
        }

        Element[][] exps = new Element[2][3];
        for (int z = 0; z < 2; z++){
            for (int k = 0; k < 3; k++){
                exps[z][k] = tmp[k].mul(ainvs[z]);
            }
        }
        Element sigma_y;
        Element[][] sk_y_z = new Element[attrs.length][3];
        byte[][] conps = new byte[][]{null, new byte[2]};
        for(int i = 0; i < attrs.length; i++){
            sigma_y = zr.newRandomElement();
            conps[0] = attrs[i].getBytes();
            for(int z = 0; z < 2; z++){
                sk_y_z[i][z] = g.powZn(sigma_y.duplicate().mul(ainvs[z]));
                conps[1][1] = (byte) (z + 1);
                for (int k = 0; k < 3; k++) {
                    conps[1][0] = (byte) (k + 1);
                    sk_y_z[i][z] = sk_y_z[i][z].mul(
                            Utils.HashesE(conps, g1).powZn(exps[z][k])
                    );
                }
                sk_y_z[i][z] = sk_y_z[i][z].getImmutable();
            }
            sk_y_z[i][2] = g.powZn(sigma_y.negate()).getImmutable();
        }

        Element sigma_p = zr.newRandomElement();
        Element[] g_sig_a_s = new Element[]{
                g.powZn(sigma_p.duplicate().mul(ainvs[0])),
                g.powZn(sigma_p.duplicate().mul(ainvs[1]))
        };
        Element[] sk_s_p = new Element[2];
        byte[] conps_p = new byte[]{0,1,0,0};
        for(int z = 0; z < 2; z++){
            sk_s_p[z] = g_dz[z];
            conps_p[3] = (byte) (z + 1);
            for (int k = 0; k < 3; k++) {
                conps_p[2] = (byte) (k + 1);
                sk_s_p[z] = sk_s_p[z].mul(
                        Utils.HashE(conps_p, g1).powZn(exps[z][k])
                );
            }
            sk_s_p[z] = sk_s_p[z].mul(g_sig_a_s[z]).getImmutable();
        }

        Integer[] thetas = this.st.getPath(this.st.getMappedId(id));
        Element[] sk_theta = new Element[thetas.length];
        Element g_theta;
        Element tmpE = g_dz[2].mul(
                g.powZn(sigma_p.duplicate().negate())
        );
        for (int i = 0; i < thetas.length; i++) {
//            if(this.st.getNodes()[thetas[i]] == null)
//                this.st.getNodes()[thetas[i]] = g1.newRandomElement().getImmutable();
            g_theta = this.st.getNodes()[thetas[i]];
            sk_theta[i] = tmpE.duplicate().mul(g_theta.invert()).getImmutable();
        }

        RABEUSK usk = new RABEUSK(id, sk0, sk_y_z, sk_s_p, sk_theta, thetas, attrs);
        return usk;
    }

    public RABEUpdateK kupdate(long t){
        Integer[] thetas = this.st.kunodes(this.rl, t).toArray(new Integer[0]);

        Field zr = this.mpk.getPairing().getZr();
        Field g1 = this.mpk.getPairing().getG1();
        Element g_theta, r_theta;
        Element[][] ku_thetas = new Element[thetas.length][2];
        byte[][] conps = new byte[][]{
                new byte[]{1}, Utils.long2bytes(t)
        };
        for (int i = 0; i < thetas.length; i++) {
            g_theta = this.st.getNodes()[thetas[i]];
            r_theta = zr.newRandomElement();
            ku_thetas[i][0] = g_theta.mul(
                    Utils.HashesE(
                            conps, g1).powZn(r_theta)
            ).getImmutable();
            ku_thetas[i][1] = this.msk.getH().powZn(r_theta).getImmutable();
        }

        return new RABEUpdateK(t, thetas, ku_thetas);
    }

    public RABEDK dkgen(RABEUSK sk, RABEUpdateK upk){
        List<Integer> ku_list = Arrays.asList(upk.getThetas());
        List<Integer> sk_list = Arrays.asList(sk.getThetas());
        Set<Integer> kunodes = new HashSet<>(ku_list);
        Set<Integer> ps = new HashSet<>(sk_list);
        ps.retainAll(kunodes);
        if(ps.size() < 1) {
            //System.out.println("can not gen dk for uset " + sk.getUid() + " !");
            return null;
        }
        if(ps.size() > 1){
            System.out.println("Error! should only one node");
            return null;
        }

        Integer theta = ps.toArray(new Integer[0])[0];
        int sk_index = sk_list.indexOf(theta);
        int upk_index = ku_list.indexOf(theta);

        Element r = this.mpk.getPairing().getZr().newRandomElement();
        Element[] sk_p = new Element[4];

        byte[][] conps = new byte[][]{
                new byte[]{1}, Utils.long2bytes(upk.getT())
        };
        sk_p[0] = sk.getSk_p()[0];
        sk_p[1] = sk.getSk_p()[1];
        sk_p[2] = sk.getSk_theta()[sk_index].mul(
                upk.getKu_thetas()[upk_index][0]
        ).mul(
                Utils.HashesE(
                        conps, this.mpk.getPairing().getG1()
                ).powZn(r)
        ).getImmutable();
        sk_p[3] = upk.getKu_thetas()[upk_index][1].mul(
                this.msk.getH().powZn(r)
        ).getImmutable();

        return new RABEDK(sk.getAttrs(), upk.getT(), sk.getSk0(), sk.getSk_y(), sk_p);
    }

    public void revoke(int uid, long t){
        if(!this.rl.contains(uid))
            this.rl.add(uid, t);
    }

    public RABEMSK getMsk() {
        return msk;
    }

    public RABEMPK getMpk() {
        return mpk;
    }

    public RevokeList getRl() {
        return rl;
    }

    public KUNodes getSt() {
        return st;
    }
}
