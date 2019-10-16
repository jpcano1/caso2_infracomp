package servidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class P {
    private static ServerSocket ss;
    private static final String MAESTRO = "MAESTRO: ";
    private static X509Certificate certSer;
    private static KeyPair keyPairServidor;

    public P() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println("MAESTRO: Establezca puerto de conexion:");
        InputStreamReader isr = new InputStreamReader(System.in);
        BufferedReader br = new BufferedReader(isr);
//        int ip = Integer.parseInt(br.readLine());
        int ip = 5555;
        System.out.println("MAESTRO: Empezando servidor maestro en puerto " + ip);
        Security.addProvider(new BouncyCastleProvider());
        int idThread = 0;
        ss = new ServerSocket(ip);
        System.out.println("MAESTRO: Socket creado.");
        keyPairServidor = S.grsa();
        certSer = S.gc(keyPairServidor);
        D.initCertificate(certSer, keyPairServidor);

        while(true) {
            while(true) {
                try {
                    Socket sc = ss.accept();
                    System.out.println("MAESTRO: Cliente " + idThread + " aceptado.");
                    D d = new D(sc, idThread);
                    ++idThread;
                    d.start();
                } catch (IOException var7) {
                    System.out.println("MAESTRO: Error creando el socket cliente.");
                    var7.printStackTrace();
                }
            }
        }
    }
}

