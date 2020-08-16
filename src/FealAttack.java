import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class FealAttack {
    List<String> plainTexts = new ArrayList<>();
    List<String> cipherTexts = new ArrayList<>();
    List<Long> keyCandidates = new ArrayList<>();

    void myEncrypt(int key[], byte[] data) {
        FEAL.encrypt(data, key);
    }

    void myDecrypt(int key[], byte[] data) {
        FEAL.encrypt(data, key);
    }

    void loadPlainTextCipherTextPairs() throws IOException {
        FileInputStream fstream = null;
        fstream = new FileInputStream("known.txt");
        BufferedReader br = new BufferedReader(new InputStreamReader(fstream));
        String keyLine;
        
        while ((keyLine = br.readLine()) != null) {
            if (keyLine.length() > 0) {
                //plainToCipherTexts.put(keyLine , valLine);
                if (keyLine.contains("Plaintext")) {
                    plainTexts.add(keyLine.substring(12));
                }
                if (keyLine.contains("Ciphertext")) {
                    cipherTexts.add(keyLine.substring(12));
                }
            }
        }

        fstream.close();

        System.out.println(plainTexts.size());
        System.out.println(plainTexts);
        System.out.println(cipherTexts.size());
        System.out.println(cipherTexts);
    }

    String getLhalf(String s) {
        return s.substring(0, 8);
    }

    String getRhalf(String s) {
        return s.substring(8);
    }

    int get64BitIntFromHex(String s) {
        return (int) Long.parseLong(s, 16);

    }

    private long getBit(long num, int n) {
        return (num >> (31 - n)) & 1;
    }

    void doBruteForceAttack() throws IOException {
        loadPlainTextCipherTextPairs();
        int keyPairCount = plainTexts.size();

        // 32 bit keyspace
        for (long putativeKey = 0; putativeKey < 4294967296L; putativeKey++) {
            int[] count = new int[2];
            count[0] = 0;
            count[1] = 0;

            for (int i = 0; i < keyPairCount; i++) {
                long unknownConstant = getUnknownConstantforA1(putativeKey, i);

                if (unknownConstant == 0) {
                    count[0]++;
                } else {
                    count[1]++;
                }
            }
            if (count[0] == keyPairCount || count[1] == keyPairCount) {
                keyCandidates.add(putativeKey);
            }
        }
    }

    private long getUnknownConstantforA1(long putativeKey, int i) {
        String l0 = getLhalf(plainTexts.get(i)); // 4bytes (32 bits)
        String r0 = getRhalf(plainTexts.get(i));
        String l4 = getLhalf(cipherTexts.get(i));
        String r4 = getRhalf(cipherTexts.get(i));

        long L0 = Long.parseLong(l0, 16);
        long R0 = Long.parseLong(r0, 16);
        long L4 = Long.parseLong(l4, 16);
        long R4 = Long.parseLong(r4, 16);

        // a=S23,29(L0 ⊕R0 ⊕L4) ⊕ S31(L0 ⊕L4 ⊕R4) ⊕ S31F(L0 ⊕ R0 ⊕ K0)

        // a1 = S23,29(L0 ⊕R0 ⊕L4)
        long a1 = getBit(L0 ^ R0 ^ L4, 23) ^ getBit(L0 ^ R0 ^ L4, 29);

        // a2 = S31(L0 ⊕L4 ⊕R4)
        long a2 = getBit(L0 ^ L4 ^ R4, 31);

        // a3 = S31F(L0 ⊕ R0 ⊕ K0)
        long parameter = L0 ^ R0 ^ putativeKey;
        int result = FEAL.f((int) parameter);
        long a3 = getBit(result, 31);

        return a1 ^ a2 ^ a3;
    }


    public void doFastAttackK0() throws IOException {
        loadPlainTextCipherTextPairs();
        int keyPairCount = plainTexts.size();

        // 16 bit keyspace
        for (long putativeKey = 0; putativeKey < 65536L; putativeKey++) {
            int[] count = new int[2];
            count[0] = 0;
            count[1] = 0;

            for (int i = 0; i < keyPairCount; i++) {
                long unknownConstant = getUnknownConstantforA2(putativeKey, i);

                if (unknownConstant == 0) {
                    count[0]++;
                } else {
                    count[1]++;
                }
            }
            if (count[0] == keyPairCount || count[1] == keyPairCount) {
                keyCandidates.add(putativeKey);
            }
        }
    }

    private long getUnknownConstantforA2(long putativeKey, int i) {
        String l0 = getLhalf(plainTexts.get(i)); // 4bytes (32 bits)
        String r0 = getRhalf(plainTexts.get(i));
        String l4 = getLhalf(cipherTexts.get(i));
        String r4 = getRhalf(cipherTexts.get(i));

        long L0 = Long.parseLong(l0, 16);
        long R0 = Long.parseLong(r0, 16);
        long L4 = Long.parseLong(l4, 16);
        long R4 = Long.parseLong(r4, 16);

        // a = S5,13,21(L0⊕R0⊕L4)⊕S15(L0⊕L4⊕R4)⊕S15(F(L0⊕R0⊕K’0))

        // a1 = S5,13,21(L0⊕R0⊕L4)
        long a1 =
                getBit(L0 ^ R0 ^ L4, 5) ^
                getBit(L0 ^ R0 ^ L4, 13) ^
                getBit(L0 ^ R0 ^ L4, 21);

        // a2 = S15(L0⊕L4⊕R4)
        long a2 = getBit(L0 ^ L4 ^ R4, 15);

        // a3 = S15(F(L0⊕R0⊕K’0))
        long parameter = L0 ^ R0 ^ putativeKey;
        int result = FEAL.f((int) parameter);
        long a3 = getBit(result, 15);

        return a1 ^ a2 ^ a3;
    }

    public List<Long> getKeyCandidates() {
        return keyCandidates;
    }

    public static void main(String args[]) throws IOException {
        FealAttack fealAttack = new FealAttack();
        //fealAttack.doBruteForceAttack();
        fealAttack.doFastAttackK0();
        System.out.println("Summary");
        System.out.println(fealAttack.getKeyCandidates());
    }
}
