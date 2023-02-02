import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
//import smu.smc.dcph.Utils;
//import smu.smc.lsss.LSSSMatrix;
//import smu.smc.lsss.Vector;

public class RABEEngine {
    private RABEMPK mpk;
    private RABEMSK msk;

    public RABEEngine(RABEMPK mpk, RABEMSK msk) {
        this.mpk = mpk;
        this.msk = msk;
    }

    public RABECipher enc(Element m, LSSSMatrix policy, long t){

        Field zr = this.mpk.getPairing().getZr();
        Element[] ss = new Element[]{
                zr.newRandomElement(),
                zr.newRandomElement()};

        return enc(m, policy, t, ss);
    }

    public RABECipher enc(Element m, LSSSMatrix policy, long t, Element[] ss){
        Field g1 = this.mpk.getPairing().getG1();

        Element[] c0 = new Element[4];
        Element sums = ss[0].duplicate().add(ss[1]);
        c0[0] = this.mpk.getH1().powZn(ss[0]).getImmutable();
        c0[1] = this.mpk.getH2().powZn(ss[1]).getImmutable();
        c0[2] = this.msk.getH().powZn(sums).getImmutable();
        c0[3] = Utils.HashesE(
                new byte[][]{
                        new byte[]{1}, Utils.long2bytes(t)
                }, g1).powZn(sums).getImmutable();

        int row = policy.getRows();
        int col = policy.getCols();
        Element[][] cs = new Element[row][3];
        byte[][] tmpbytes = new byte[][]{null, new byte[]{0,0}};
        byte[] tmpbyte = new byte[]{0,0,0,0};
        Element tmpe;
        for (int i = 0; i < row; i ++){
            for (int l = 0; l < 3; l ++){
                tmpbytes[0] = policy.getMap()[i].getBytes();
                tmpbytes[1][0] = (byte) (l + 1);
                cs[i][l] = g1.newOneElement();
                for(int z = 0; z < 2; z++){
                    tmpbytes[1][1] = (byte) (z + 1);
                    cs[i][l] = cs[i][l].mul(
                            Utils.HashesE(
                                    tmpbytes, g1
                            ).powZn(ss[z])
                    );
                }

                tmpbyte[2] = (byte) (l + 1);
                for (int j = 0; j < col; j++) {
//                    tmpbyte[1] = (byte) (j + 1);
                    tmpbyte[1] = 1;
                    tmpe = g1.newOneElement();
                    for(int kk = 0; kk < 2; kk++){
                        tmpbyte[3] = (byte) (kk + 1);
                        tmpe = tmpe.mul(
                                Utils.HashE(
                                        tmpbyte, g1
                                ).powZn(ss[kk])
                        );
                    }
                    tmpe = tmpe.powZn(policy.getMatrix().getValue(i,j));
                    cs[i][l] = cs[i][l].mul(tmpe);

                }
                cs[i][l] = cs[i][l].getImmutable();
            }
        }

        Element c_p = this.mpk.getT1().powZn(ss[0]).mul(
                this.mpk.getT2().powZn(ss[1])
        ).mul(m).getImmutable();

        return new RABECipher(policy, t, c0, cs, c_p);
    }

    public Element decrypt(RABEDK dk, RABECipher cipher){

        Field g1 = this.mpk.getPairing().getG1();
        Field gt = this.mpk.getPairing().getGT();
        Pairing pairing = this.mpk.getPairing();

        int[][] indexes = Utils.search(
                cipher.getPolicy().getMap(),
                dk.getAttrs()
        );
        int[] ci = indexes[0];
        int[] ui = indexes[1];
        Vector lambda = cipher.getPolicy().extract(ci).genLambda();

        Element[] tmp1 = new Element[3];
        Element[] tmp2 = new Element[3];
        for (int i = 0; i < 3; i++) {
            tmp1[i] = g1.newOneElement();
            tmp2[i] = dk.getSk_p()[i];
        }
        for (int i = 0; i < ci.length; i++) {
            for (int j = 0; j < 3; j++) {
                tmp1[j] = tmp1[j].mul(
                        cipher.getCs()[ci[i]][j].powZn(lambda.getValue(i))
                );
                tmp2[j] = tmp2[j].mul(
                        dk.getSk_y()[ui[i]][j].powZn(lambda.getValue(i))
                );
            }
        }

        Element num = cipher.getC_p();
        Element den = gt.newOneElement();
        for (int j = 0; j < 3; j++) {
            num = num.mul(
                    pairing.pairing(tmp1[j], dk.getSk0()[j])
            );
            den = den.mul(
                    pairing.pairing(tmp2[j], cipher.getC0()[j])
            );
        }

        num = num.mul(
                pairing.pairing(cipher.getC0()[3], dk.getSk_p()[3])
        );

        Element rm = num.mul(den.invert());

        return rm;
    }
}
