package main;

import cliente.Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Main
{
	public static void main(String[] args) throws IOException
	{
		Socket socket = null;

		PrintWriter escritor = null;

		BufferedReader lector = null;

		System.out.println("Cliente... ");

		try
		{
			socket = new Socket(Cliente.SERVIDOR, Cliente.PUERTO);

			escritor = new PrintWriter(socket.getOutputStream(), true);

			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.exit(-1);
		}

		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		Cliente cliente = new Cliente();
		cliente.procesar(stdIn, lector, escritor);

		stdIn.close();
		escritor.close();
		lector.close();
		socket.close();
	}
}
