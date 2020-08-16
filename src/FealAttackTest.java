import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class FealAttackTest {

    @Test
    public void testSetup() {
        int key[]={0x0,0x0,0x0,0x0,0x0,0x0};
        String inputText = "0 1 2 3 4e 5a f6 37";
        byte[] data = getInputTextInBytes(inputText);
        logBytes(data, "Plaintext=  ");
        FealAttack fealAttack = new FealAttack();

        fealAttack.myEncrypt(key, data);

        logBytes(data, "Ciphertext= ");
        fealAttack.myDecrypt(key, data);
        logBytes(data, "Plaintext=  ");
    }

    private void logBytes(byte[] data, String s) {
        System.out.print(s);
        for (int i = 0; i < 8; i++) System.out.printf("%02x", data[i]);
        System.out.print("\n");
    }

    private byte[] getInputTextInBytes(String inputText) {
        byte[] data = new byte[8];
        String[] args = inputText.split(" ");
        for (int i=0;i<8;i++)
           data[i] = (byte)(Integer.parseInt(args[i],16)&255);
        return data;
    }

    @Test
    public void loadPlainTextCipherTextPairsTest() throws IOException {
        FealAttack fealAttack = new FealAttack();
        fealAttack.loadPlainTextCipherTextPairs();
    }

    @Test
    public void getLhalfTest() {
        // 8 bytes (64bits) in hex
        String s = "a7f1d92a82c8d8fe";
        FealAttack fealAttack = new FealAttack();

        String lh = fealAttack.getLhalf(s);

        // 4 bytes (32bits)
        // Subkeys are also 32 bits
        assertEquals("a7f1d92a", fealAttack.getLhalf(s));
        assertEquals(-1477322454, fealAttack.get64BitIntFromHex(lh));
    }

    @Test
    public void getRhalfTest() {
        String s = "a7f1d92a82c8d8fe";
        FealAttack fealAttack = new FealAttack();

        String rh = fealAttack.getRhalf(s);

        assertEquals("82c8d8fe", rh);
        assertEquals(-2100766466, fealAttack.get64BitIntFromHex(rh));
    }


    @Disabled
    @Test
    public void attackBruteForceK0() throws IOException {
        FealAttack fealAttack = new FealAttack();
        fealAttack.doBruteForceAttack();
        System.out.println("Summary");
        System.out.println(fealAttack.getKeyCandidates());
    }

    @Test
    public void attackFasterK0() throws IOException {
        FealAttack fealAttack = new FealAttack();
        fealAttack.doFastAttackK0();
        System.out.println("Summary");
        System.out.println(fealAttack.getKeyCandidates());
    }

}