package cliente;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class Cliente
{
    /**
     * Servidor - Puerto
     */
    public static final int PUERTO = 5555;
    public static final String SERVIDOR = "localhost";

    /**
     * Cadenas de control
     */
    public static final String HOLA = "HOLA";
    public static final String ALGORITMOS = "ALGORITMOS";
    public final static String OK = "OK";
    public final static String ERROR = "ERROR";

    /**
     * Algoritmos en string
     */
    public static final String AES = "AES";
    public static final String BLOWFISH = "Blowfish";
    public static final String RSA = "RSA";
    public static final String HMACSHA1 = "HMACSHA1";
    public static final String HMACSHA256 = "HMACSHA256";
    public static final String HMACSHA384 = "HMACSHA384";
    public static final String HMACSHA512 = "HMACSHA512";

    /**
     *
     */
    private static SecretKey symmetricKey;

    /**
     *
     */
    private static ArrayList<String> algos;

    /**
     *
     */
    public Cliente()
    {
        KeyGenerator keyGen;
        algos = new ArrayList<String>();
        try
        {
            keyGen = KeyGenerator.getInstance(AES);
            symmetricKey = keyGen.generateKey();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    /**
     *
     */
    static void menuSimetrico() {
        System.out.println("1. AES ");
        System.out.println("2. Blowfish (No disponible)");
    }

    /**
     *
     */
    static void menuHmac() {
        System.out.println("1. HmacSHA1");
        System.out.println("2. HmacSHA256");
        System.out.println("3. HmacSHA384");
        System.out.println("4. HmacSHA512");
    }

    /**
     *
     * @param stdIn
     */
    private static void chooseAlgos(BufferedReader stdIn)
    {
        System.out.println("Escoja uno de estos algoritmos simetricos: ");
        try
        {
            menuSimetrico();
            int selection = Integer.parseInt(stdIn.readLine());
            switch (selection)
            {
                case 1:
                    algos.add(AES);
                    break;

                case 2:
                    System.out.println("No disponible, es usará AES por defecto");
                    algos.add(AES);
                    break;
            }
            System.out.println("Escoja uno de estos algoritmos de hashing: ");
            menuHmac();
            selection = Integer.parseInt(stdIn.readLine());

            switch (selection)
            {
                case 1:
                    algos.add(HMACSHA1);
                    break;

                case 2:
                    algos.add(HMACSHA256);
                    break;

                case 3:
                    algos.add(HMACSHA384);
                    break;

                case 4:
                    algos.add(HMACSHA512);
                    break;
            }
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
    }

    /**
     *
     * @param pReto
     * @param fromServer
     * @return
     */
    public static boolean validateReto(String pReto, byte[] fromServer)
    {
        try
        {
            Cipher cipher = Cipher.getInstance(algos.get(0));
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            String msg = DatatypeConverter.printBase64Binary(cipher.doFinal(fromServer));
            while(pReto.length() != msg.length())
            {
                pReto += 0;
            }
            if(msg.equals(pReto))
            {
                return true;
            }
        }
        catch(Exception e)
        {
            System.out.println(e.getMessage());
            return false;
        }
        return false;
    }

    /**
     *
     * @param msg
     * @return
     */
    private static byte[] encryptS(byte[] msg)
    {
        byte[] bytes = null;
        try
        {
            Cipher cipher = Cipher.getInstance(algos.get(0));
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            bytes = cipher.doFinal(msg);
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        return bytes;
    }

    /**
     *
     * @param msg
     * @return
     */
    private static byte[] decryptS(byte[] msg)
    {
        byte[] bytes = null;
        try
        {
            Cipher cipher = Cipher.getInstance(algos.get(0));
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            bytes = cipher.doFinal(msg);
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        return bytes;
    }

    private static byte[] decryptA(byte[] msg, PublicKey ks)
    {
        byte[] bytes = null;
        try
        {
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(cipher.DECRYPT_MODE, ks);
            bytes = cipher.doFinal(msg);
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        return bytes;
    }

    /**
     *
     * @param msg
     * @param ks
     * @return
     */
    private static byte[] encryptA(byte[] msg, PublicKey ks)
    {
        byte[] bytes = null;
        try
        {
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.ENCRYPT_MODE, ks);
            bytes = cipher.doFinal(msg);
        }
        catch(Exception e)
        {
            System.out.println(e.getMessage());
        }
        return bytes;
    }

    /**
     *
     * @param msg
     * @return
     */
    private static byte[] encryptHmac(byte[] msg)
    {
        byte[] bytes = null;
        try
        {
            Mac mac = Mac.getInstance(algos.get(1));
            mac.init(symmetricKey);
            bytes = mac.doFinal(msg);
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        return bytes;
    }

    /**
     *
     * @param msg
     * @return
     */
    private static byte[] toBytesArray(String msg)
    {
        String final_ = msg;
        while(final_.length() % 4 != 0) final_ += 0;
        byte[] bytes = DatatypeConverter.parseBase64Binary(final_);
        return bytes;
    }

    /**
     *
     * @param msg
     * @param hash
     * @return
     */
    private static boolean validateHmac(byte[] msg, byte[] hash)
    {
        if(msg.length != hash.length)
        {
            return false;
        }
        else
        {
            for(int i = 0; i < msg.length; ++i) {
                if (msg[i] != hash[i]) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     *
     * @param stdIn
     * @param pIn
     * @param pOut
     * @throws IOException
     */
    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException
    {
        chooseAlgos(stdIn);
        String fromUser = HOLA;
        pOut.println(fromUser);

        pIn.readLine();

        // Send Algorithms
        fromUser = ALGORITMOS + ":" + algos.get(0) + ":" + RSA + ":" + algos.get(1);

        pOut.println(fromUser);

        // Must receive OK
        String fromServer = pIn.readLine();

        System.out.println(fromServer);

        // Receives certificate
        String cert = pIn.readLine();

        try
        {
            // Converts Cert to byte Array
            InputStream is = new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(cert));
            // Creates the certificate factory
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(is);

            // Gets public key from server
            PublicKey ks = certificate.getPublicKey();

            // Ciphers the symmetric Key with RSA
            byte[] userMsg = encryptA(symmetricKey.getEncoded(), ks);

            // Sends the symmetric Key
            fromUser = DatatypeConverter.printBase64Binary(userMsg);
            pOut.println(fromUser);

            // Envía reto
            System.out.println("Ingrese un mensaje:");
            fromUser = stdIn.readLine();
            userMsg = toBytesArray(fromUser);
            pOut.println(DatatypeConverter.printBase64Binary(userMsg));
            String reto = fromUser;

            // Recibe reto encriptado
            fromServer = pIn.readLine();
            byte[] serverMsg = toBytesArray(fromServer);

            // Valida que el reto sea el mismo
            boolean validation = validateReto(reto, serverMsg);

            // Envia respuesta
            if(validation)
            {
                pOut.println(OK);
            }
            else
            {
                pOut.println(ERROR);
            }

            System.out.println("Ingrese su cédula: ");
            fromUser = stdIn.readLine();

            userMsg = encryptS(toBytesArray(fromUser));
            pOut.println(DatatypeConverter.printBase64Binary(userMsg));

            System.out.println("Ingrese su clave: ");
            fromUser = stdIn.readLine();
            userMsg = encryptS(toBytesArray(fromUser));
            pOut.println(DatatypeConverter.printBase64Binary(userMsg));

            fromServer = pIn.readLine();
            serverMsg = toBytesArray(fromServer);
            serverMsg = decryptS(serverMsg);
            byte[] msg = encryptHmac(serverMsg);

            fromServer = pIn.readLine();
            serverMsg = toBytesArray(fromServer);
            byte[] hash = decryptA(serverMsg, ks);

            validation = validateHmac(msg, hash);
            if(validation)
            {
                pOut.println(OK);
            }
            else
            {
                pOut.println(ERROR);
            }
        }
        catch(Exception e)
        {
            System.out.println(e.getMessage());
        }
    }
}
