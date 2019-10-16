package servidor;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Random;
import javax.xml.bind.*;

public class D extends Thread {
    public static final String OK = "OK";
    public static final String ALGORITMOS = "ALGORITMOS";
    public static final String CERTSRV = "CERTSRV";
    public static final String CERCLNT = "CERCLNT";
    public static final String SEPARADOR = ":";
    public static final String HOLA = "HOLA";
    public static final String INICIO = "INICIO";
    public static final String ERROR = "ERROR";
    public static final String REC = "recibio-";
    private Socket sc = null;
    private String dlg;
    private byte[] mybyte;
    private static X509Certificate certSer;
    private static KeyPair keyPairServidor;

    public D(Socket csP, int idP) {
        this.sc = csP;
        this.dlg = new String("delegado " + idP + ": ");

        try {
            this.mybyte = new byte[520];
            this.mybyte = certSer.getEncoded();
        } catch (Exception var4) {
            System.out.println("Error creando encoded del certificado para el thread" + this.dlg);
            var4.printStackTrace();
        }

    }

    public static void initCertificate(X509Certificate pCertSer, KeyPair pKeyPairServidor) {
        certSer = pCertSer;
        keyPairServidor = pKeyPairServidor;
    }

    private boolean validoAlgHMAC(String nombre) {
        return nombre.equals("HMACMD5") || nombre.equals("HMACSHA1") || nombre.equals("HMACSHA256") || nombre.equals("HMACSHA384") || nombre.equals("HMACSHA512");
    }

    public void run() {
        System.out.println(this.dlg + "Empezando atencion.");

        try {
            PrintWriter ac = new PrintWriter(this.sc.getOutputStream(), true);
            BufferedReader dc = new BufferedReader(new InputStreamReader(this.sc.getInputStream()));
            String linea = dc.readLine();
            if (!linea.equals("HOLA")) {
                ac.println("ERROR");
                this.sc.close();
                throw new Exception(this.dlg + "ERROR" + "recibio-" + linea + "-terminando.");
            }

            ac.println("OK");
            System.out.println(this.dlg + "recibio-" + linea + "-continuando.");
            linea = dc.readLine();
            if (!linea.contains(":") || !linea.split(":")[0].equals("ALGORITMOS")) {
                ac.println("ERROR");
                this.sc.close();
                throw new Exception(this.dlg + "ERROR" + "recibio-" + linea + "-terminando.");
            }

            String[] algoritmos = linea.split(":");
            if (!algoritmos[1].equals("DES") && !algoritmos[1].equals("AES") && !algoritmos[1].equals("Blowfish") && !algoritmos[1].equals("RC4")) {
                ac.println("ERROR");
                this.sc.close();
                throw new Exception(this.dlg + "ERROR" + "Alg.Simetrico" + "recibio-" + algoritmos + "-terminando.");
            }

            if (!algoritmos[2].equals("RSA")) {
                ac.println("ERROR");
                this.sc.close();
                throw new Exception(this.dlg + "ERROR" + "Alg.Asimetrico." + "recibio-" + algoritmos + "-terminando.");
            }

            if (!this.validoAlgHMAC(algoritmos[3])) {
                ac.println("ERROR");
                this.sc.close();
                throw new Exception(this.dlg + "ERROR" + "AlgHash." + "recibio-" + algoritmos + "-terminando.");
            }

            System.out.println(this.dlg + "recibio-" + linea + "-continuando.");
            ac.println("OK");
            ac.println(toHexString(this.mybyte));
            System.out.println(this.dlg + "envio certificado del servidor. continuando.");
            linea = dc.readLine();
            byte[] llaveSimetrica = S.ad(toByteArray(linea), keyPairServidor.getPrivate(), algoritmos[2]);
            SecretKey simetrica = new SecretKeySpec(llaveSimetrica, 0, llaveSimetrica.length, algoritmos[1]);
            System.out.println(this.dlg + "recibio y creo llave simetrica. continuando.");
            linea = dc.readLine();
            System.out.println(this.dlg + "Recibio reto del cliente:-" + linea + "-");
            byte[] retoByte = toByteArray(linea);
            byte[] ciphertext1 = S.se(retoByte, simetrica, algoritmos[1]);
            ac.println(toHexString(ciphertext1));
            System.out.println(this.dlg + "envio reto cifrado con llave simetrica al cliente. continuado.");
            linea = dc.readLine();
            if (!linea.equals("OK")) {
                this.sc.close();
                throw new Exception(this.dlg + "ERROR" + "en confirmacion de llave simetrica." + "recibio-" + "-terminando.");
            }

            System.out.println(this.dlg + "recibio confirmacion del cliente:" + linea + "-continuado.");
            linea = dc.readLine();
            byte[] var9 = S.sd(toByteArray(linea), simetrica, algoritmos[1]);
            String cc = toHexString(var9);
            System.out.println(this.dlg + "recibio cc y descifro:-" + cc + "-continuado.");
            linea = dc.readLine();
            byte[] var11 = S.sd(toByteArray(linea), simetrica, algoritmos[1]);
            String clave = toHexString(var11);
            System.out.println(this.dlg + "recibio clave y descifro:-" + clave + "-continuado.");
            Random var13 = new Random();
            int valor = var13.nextInt(1000000);

            String strvalor;
            for(strvalor = String.valueOf(valor); strvalor.length() % 4 != 0; strvalor = strvalor + 0) {
            }

            byte[] valorByte = toByteArray(strvalor);
            byte[] ciphertext2 = S.se(valorByte, simetrica, algoritmos[1]);
            ac.println(toHexString(ciphertext2));
            System.out.println(this.dlg + "envio valor " + strvalor + " cifrado con llave simetrica al cliente. continuado.");
            byte[] hmac = S.hdg(valorByte, simetrica, algoritmos[3]);
            byte[] recibo = S.ae(hmac, keyPairServidor.getPrivate(), algoritmos[2]);
            ac.println(toHexString(recibo));
            System.out.println(this.dlg + "envio hmac cifrado con llave privada del servidor. continuado.");
            linea = dc.readLine();
            if (linea.equals("OK")) {
                System.out.println(this.dlg + "Terminando exitosamente." + linea);
            } else {
                System.out.println(this.dlg + "Terminando con error" + linea);
            }

            this.sc.close();
        } catch (Exception var20) {
            var20.printStackTrace();
        }

    }

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printBase64Binary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseBase64Binary(s);
    }
}

