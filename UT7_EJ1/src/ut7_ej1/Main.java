/*
Ejercicio 1.
De igual manera a lo visto en el tema, ahora te proponemos un ejercicio que 
genere una cadena de texto y la deje almacenada en un fichero encriptado, 
en la raíz del proyecto hayas creado, con el nombre fichero.cifrado.

Para encriptar el fichero, utilizarás el algoritmo Rijndael o AES, con las 
especificaciones de modo y relleno siguientes: Rijndael/ECB/PKCS5Padding.

La clave, la debes generar de la siguiente forma:
A partir de un número aleatorio con semilla la cadena del nombre de usuario + password.
Con una longitud o tamaño 128 bits.

 */
package ut7_ej1;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author JM_B
 */
public class Main {
    
   static  File fichero;
   static String mensaje="FICHERO CIFRADO UT6 JM_B\nEjercicio 1.\n" +
"De igual manera a lo visto en el tema, ahora te proponemos un ejercicio que \n" +
"genere una cadena de texto y la deje almacenada en un fichero encriptado, \n" +
"en la raíz del proyecto hayas creado, con el nombre fichero.cifrado.\n" +
"\n" +
"Para encriptar el fichero, utilizarás el algoritmo Rijndael o AES, con las \n" +
"especificaciones de modo y relleno siguientes: Rijndael/ECB/PKCS5Padding.\n" +
"\n" +
"La clave, la debes generar de la siguiente forma:\n" +
"A partir de un número aleatorio con semilla la cadena del nombre de usuario + password.\n" +
"Con una longitud o tamaño 128 bits.";
    
    //método que encripta el fichero que se pasa como parámetro
  //devuelve el valor de la clave privada utilizada en encriptación
  //El fichero encriptado lo deja en el archivo de nombre fichero.cifrado en el mismo directorio
   
private static SecretKey cifrarFichero(String file, String texto,int letrasUsuarioPass) 
        throws NoSuchAlgorithmException, NoSuchPaddingException, FileNotFoundException, 
        IOException, IllegalBlockSizeException,BadPaddingException, InvalidKeyException {
 //se crea y escribe el fichero      
        PrintWriter prnt = null;
    try {
        fichero = new File(file);
        FileWriter flWrtr = new FileWriter(fichero); 
        BufferedWriter bfWrt = new BufferedWriter(flWrtr); 
        prnt = new PrintWriter(bfWrt);
        prnt.write(texto);
 //se cierra el print y el bufferedWriter 
        prnt.close();
        bfWrt.close();
        
    } catch (FileNotFoundException ex) {
        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
    } catch (IOException ex) {
        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
    } 
 //lo flujos de entrada y salida
    FileInputStream fe = null; //fichero de entrada
    FileOutputStream fs = null; //fichero de salida
    int bytesLeidos;

//1. Crear e inicializar clave
    System.out.println("1.-Genera clave AES");
    
//crea un objeto para generar la clave usando algoritmo AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

//se crea un objeto de la clase ramdonSecure con el algoritmo de Hash seguro
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//se le pasa el argumento de un int para el tamño de la semilla
//en este caso se pasará el total de caracteres de usaurio+contrseña
        random.setSeed(letrasUsuarioPass);
//    keyGen.init(128); //se indica el tamaño de la clave 
//y se pasa el objeto random
        keyGen.init(128,random); 
//genera la clave privada
    SecretKey clave = keyGen.generateKey(); 

    System.out.println("Clave");
    mostrarBytes(clave.getEncoded()); //muestra la clave
    System.out.println();

//Se Crea el objeto Cipher para cifrar, utilizando el algoritmo Rijndael
    Cipher cifrador = Cipher.getInstance("Rijndael/ECB/PKCS5Padding");
    //Se inicializa el cifrador en modo CIFRADO o ENCRIPTACIÓN
//se pasa como argumento el tipo , la clave y el objeto ramdon
    cifrador.init(Cipher.ENCRYPT_MODE, clave,random);//
    System.out.println("2.- Cifrar con Rijndael el fichero: " + file+ ", y dejar resultado en " + file + ".cifrado");
//declaración  de objetos
    byte[] buffer = new byte[1000]; //array de bytes
    byte[] bufferCifrado;
    
    fe = new FileInputStream(fichero); //  fileobjeto fichero de entrada
    
    fs = new FileOutputStream(fichero + ".cifrado"); //fichero de salida
    //lee el fichero de 1k en 1k y pasa los fragmentos leidos al cifrador
    bytesLeidos = fe.read(buffer, 0, 1000);
    while (bytesLeidos != -1) {//mientras no se llegue al final del fichero
      //pasa texto claro al cifrador y lo cifra, asignándolo a bufferCifrado
      bufferCifrado = cifrador.update(buffer, 0, bytesLeidos);
      fs.write(bufferCifrado); //Graba el texto cifrado en fichero
      bytesLeidos = fe.read(buffer, 0, 1000);
    }
    bufferCifrado = cifrador.doFinal(); //Completa el cifrado
    fs.write(bufferCifrado); //Graba el final del texto cifrado, si lo hay
    //Cierra ficheros
    fe.close();
    fs.close();
    return clave;
  }
  
//método que desencripta el fichero pasado como primer parámetro file1
  //pasándole también la clave privada que necesita para desencriptar, key
  //y deja el fichero desencriptado en el tercer parámetro file2

  private static void descifrarFichero(String file1, SecretKey key, String file2) throws 
          NoSuchAlgorithmException, NoSuchPaddingException, FileNotFoundException, 
          IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
    FileInputStream fe = null; //fichero de entrada
    FileOutputStream fs = null; //fichero de salida
    int bytesLeidos;
    Cipher cifrador = Cipher.getInstance("Rijndael/ECB/PKCS5Padding");
//Cipher.getInstance("DES");
    //3.- Poner cifrador en modo DESCIFRADO o DESENCRIPTACIÓN
    cifrador.init(Cipher.DECRYPT_MODE, key);
    System.out.println("3.- Descifrar con Rijndael el fichero: " + file1 + ", y dejar en  " + file2);
    fe = new FileInputStream(file1);
    fs = new FileOutputStream(file2);
    byte[] bufferClaro;
    byte[] buffer = new byte[1000]; //array de bytes
    //lee el fichero de 1k en 1k y pasa los fragmentos leidos al cifrador
    bytesLeidos = fe.read(buffer, 0, 1000);
    while (bytesLeidos != -1) {//mientras no se llegue al final del fichero
      //pasa texto cifrado al cifrador y lo descifra, asignándolo a bufferClaro
      bufferClaro = cifrador.update(buffer, 0, bytesLeidos);
      fs.write(bufferClaro); //Graba el texto claro en fichero
      bytesLeidos = fe.read(buffer, 0, 1000);
    }
    bufferClaro = cifrador.doFinal(); //Completa el descifrado
    fs.write(bufferClaro); //Graba el final del texto claro, si lo hay
    //cierra archivos
    fe.close();
    fs.close();
  }

  //método que muestra bytes
  public static void mostrarBytes(byte[] buffer) {
    System.out.write(buffer, 0, buffer.length);
  }
  
    public void ramdomSecureNumber(){
    try {
     SecureRandom number = SecureRandom.getInstance("SHA1PRNG");
     // Generate 20 integers 0..20
     for (int i = 0; i < 20; i++) {
       System.out.println(number.nextInt(21));
     }
   } catch (NoSuchAlgorithmException nsae) { 
     // Forward to handler
   }
  
  }
  
    public static int retornaNum(){

        Scanner sc = new Scanner(System.in);  
        String [] userPass =new String[2];
        String user="";
        String pass ="";

        int total = 0;
        System.out.println("----------UT7- JM_B------------");
        System.out.println("ingrese su usuario");
        user = sc.nextLine();   
        userPass[0] = user; 
        
        System.out.println("ingrese su password");
        pass = sc.nextLine();
        userPass[1]=pass;

            for(int i=0; i< userPass.length; i++){

               total+= userPass[i].length();

               //System.out.println(userPass[i].toString());
            }
        return total;   
    }  
  
    public static SecureRandom generadorSecureRandom(int n) throws NoSuchAlgorithmException, 
            NoSuchProviderException{
        SecureRandom random = null;
        try{
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("AES");
            random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(n);
            keyGen.initialize(1024, random); 
            KeyPair pair = keyGen.genKeyPair();
        }catch(Exception e){
            return null;
        }
        return random;
    }  
  
    public void escribir(String nombreArchivo, String texto){ 
    File f;
    f = new File("nombreArchivo");
    //Escritura
    try{
        FileWriter w = new FileWriter(f);
        BufferedWriter bw = new BufferedWriter(w);
        PrintWriter wr = new PrintWriter(bw);	
        wr.write(texto);//escribimos en el archivo 
        wr.close();
        bw.close();
    }catch(IOException e){
    };
}


  
public static void main(String[] args) {      

    Scanner sc = new Scanner(System.in);  
 //variable para guardar el total de caracteres del usuario+contraseña   
        int total = retornaNum();
    System.out.println("La suma de caracteres de usario +contraseña es : "+total);
//se pide el mensaje para guardar en el fichero y cifrar  
        System.out.println("ingrese el mensaje a cifrar");
        String mensajeTeclado = sc.nextLine();
//si no se escribe nada se guarda un texto por defecto        
        if (mensajeTeclado.equals("")){
            
            mensajeTeclado="No ha escrito nada el texto por defecto es:\n"+mensaje;
        }
        
//objeto tipo key que se va a generar
        SecretKey clave = null;

//llama a los métodos que encripta/desencripta un fichero
    try {
    
//Llama al método que encripta el fichero que se pasa como parámetro
      clave = cifrarFichero("fichero",mensajeTeclado,total);
      
//Llama la método que desencripta el fichero pasado como primer parámetro
      descifrarFichero("fichero.cifrado", clave,"fichero.descifrado");
      
      
    } catch (Exception e) {
        e.printStackTrace();
         System.out.println(e.getCause());
    }
  }
    
}
