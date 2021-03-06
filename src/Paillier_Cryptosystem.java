import java.math.*;
import java.util.Scanner;


public class Paillier_Cryptosystem   {
	
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		 
		 boolean handshake = false;
	
		 boolean Computer_A,Computer_B;
		 BigInteger upperBound = MessageDecryption.getupperBound();	
		 int bits = 512;
		 Scanner keyboard = new Scanner(System.in); 
		 	System.out.println("Computer A, ready?");
		 	 Computer_A = keyboard.nextBoolean();
		 	System.out.println("Computer B, ready?");
		 	 Computer_B = keyboard.nextBoolean();
		 	if (Computer_A == true && Computer_B == true){
		 			handshake = true;
		 		} else {
		 			System.out.println("Handshake not established!");
		 			System.exit(0);
		 		}
		 	
	
		
	
		Scanner keyboardInt = new Scanner(System.in);
		    if (handshake == true){ 
			
			System.out.println("Scenario 1: In this scenario , the message is meant to be read by the receiver A , ");
			System.out.println("however the receiver B , is stealing the message and decrypts the encrypted message with \n his pair of keys.");
			System.out.println("Scenario 2: In this scenario , the message is meant to be read by the receiver B, ");
			System.out.println("however the receiver A , is stealing the message and decrypts the encrypted message with \n his pair of keys.");
			System.out.println("Scenario 3: The message is meant for both , and the procedure goes legally.");
			
			//int Scenario = keyboardInt.nextInt();
			//Creating the keys for the Receivers.
			System.out.println("Receiver A info :");
				MessageEncryption Receiver_A = new MessageEncryption();
				Receiver_A.generateKeyPair();
				BigInteger n1 = Publickey.getN();
				//BigInteger n1 = Receiver_A.getN();
				BigInteger g1 = Publickey.getG();
				BigInteger n1square = n1.multiply(n1);
				
				BigInteger Lambda_1  = 	Privatekey.getLambda();			// Privatekey extends Pailier_Cryptosystem
				BigInteger em_1  = 	Privatekey.getem();	
				Privatekey privatekey1 = new Privatekey(Lambda_1,em_1);
				Publickey publickey1 = new Publickey(n1,n1square,g1,bits);
				//-------------------------------------------------*//
				MessageEncryption Receiver_B = new MessageEncryption();
				System.out.println("Receiver B info :");
				Receiver_B.generateKeyPair();
				BigInteger n2 =Publickey.getN();
				BigInteger g2 = Publickey.getG();
				BigInteger n2square = n2.multiply(n2);
				BigInteger Lambda_2  = 	Privatekey.getLambda();			// Privatekey extends Pailier_Cryptosystem
				BigInteger em_2  = 	Privatekey.getem();	
				Privatekey privatekey2 = new Privatekey(Lambda_2,em_2);
				Publickey publickey2 = new Publickey(n2,n2square,g2,bits);
			    	//Debuging
				//System.out.printf("So n1 = %d , n2 = %d \n g1 = %d , g2 = %d \n ",n1,n2,g1,g2);  //Info Public keys
				//System.out.printf("Lambda 1 = %d , M 1 = %d \n Lambda 2 = %d , M 2 = %d \n",Lambda_1,em_1,Lambda_2,em_2);
				//------------//
			int Scenario;
			Scanner keyboardString = new Scanner(System.in);
			
			do{
				System.out.println("Type the scenario:");
				
				 Scenario = keyboardInt.nextInt();
			if (Scenario == 1 ){
				
				//--------------------------------------------//
				System.out.println("What's the Message?");
				String str = keyboardString.nextLine(); 
				BigInteger m = StringToInt(str);
				//BigInteger m = keyboard.nextBigInteger();             
				System.out.printf("The message converted to Big Integer is : %d. \n",m);
				Privatekey privatekey1_Scen1 = new Privatekey(Lambda_1,em_1);
				Publickey publickey1_Scen1 = new Publickey(n1,n1square,g1,bits);
				BigInteger EncryptedMessage1 = publickey1.encrypt(m);
				String em1 = fromBigInteger(EncryptedMessage1);
				System.out.printf("The  Encrypted message generated by receiver's A public key is : %s. \n",em1);
				
				MessageDecryption Decrypt1 = new MessageDecryption(privatekey1_Scen1,publickey1_Scen1,upperBound);
				BigInteger DecryptedMessage1 = Decrypt1.decrypt(EncryptedMessage1);
				String Dem1 = fromBigInteger(DecryptedMessage1);
				//------------------//
				Privatekey privatekey2_Scen1 = new Privatekey(Lambda_2,em_2);
				Publickey publickey2_Scen1 = new Publickey(n2,n2square,g2,bits);
				MessageDecryption Decrypt2 = new MessageDecryption(privatekey2_Scen1,publickey2_Scen1,upperBound);
				BigInteger DecryptedMessage2 = Decrypt2.decrypt(EncryptedMessage1);
				String Dem2 = fromBigInteger(DecryptedMessage2);
				 System.out.printf("The A receiver decrypts the message as : %s. \n",Dem1);
				 System.out.printf("The B receiver decrypts the message as : %s. \n",Dem2);
				 
		    }
		    else if (Scenario == 2){
				System.out.println("What's the Message?");
				String str = keyboardString.nextLine(); 
				BigInteger m = StringToInt(str);
				System.out.printf("The number is : %d. \n",m);
				System.out.printf("The message is : %s. \n",str);
				Privatekey privatekey2_Scen2 = new Privatekey(Lambda_2,em_2);
				Publickey publickey2_Scen2 = new Publickey(n2,n2square,g2,bits);
				BigInteger EncryptedMessage1 = publickey2.encrypt(m);
				
				System.out.printf("The  Encrypted message generated by receiver's B public key is : %d. \n",EncryptedMessage1);
				MessageDecryption Decrypt1 = new MessageDecryption(privatekey2_Scen2,publickey2_Scen2,upperBound);
				BigInteger DecryptedMessage1 = Decrypt1.decrypt(EncryptedMessage1);
				String em1 = fromBigInteger(DecryptedMessage1);
				//-----/////
				Privatekey privatekey1_Scen2 = new Privatekey(Lambda_1,em_1);
				Publickey publickey1_Scen2 = new Publickey(n1,n1square,g1,bits);
				MessageDecryption Decrypt2 = new MessageDecryption(privatekey1_Scen2,publickey1_Scen2,upperBound);
				BigInteger DecryptedMessage2 = Decrypt2.decrypt(EncryptedMessage1); 
				String em2 = fromBigInteger(DecryptedMessage2);
				 System.out.printf("The A receiver decrypts the message as : %s. \n",em2);
				 System.out.printf("The B receiver decrypts the message as : %s. \n",em1);
			}
			else if (Scenario == 3){
				System.out.println("What's the Message?");
				String str = keyboardString.nextLine(); 
				BigInteger m = StringToInt(str);           // messageEncryption extends Pailier_Cryptosystem
				System.out.printf("The message converted to int is : %d \n",m);
				Privatekey privatekey1_Scen3 = new Privatekey(Lambda_1,em_1);
				Publickey publickey1_Scen3 = new Publickey(n1,n1square,g1,bits);
				
				BigInteger EncryptedMessage1 = publickey1.encrypt(m);
				String em1 = fromBigInteger(EncryptedMessage1);
				MessageDecryption Decrypt1 = new MessageDecryption(privatekey1_Scen3,publickey1_Scen3,upperBound);
				BigInteger DecryptedMessage1 = Decrypt1.decrypt(EncryptedMessage1);
				String Dem1 = fromBigInteger(DecryptedMessage1);
				System.out.printf("The  Encrypted message for A is : %s \n",em1);
				 System.out.printf("The A receiver decrypts the message as : %s \n",Dem1);
				
				//------------------//
				 Privatekey privatekey2_Scen3 = new Privatekey(Lambda_2,em_2);
					Publickey publickey2_Scen3 = new Publickey(n2,n2square,g2,bits);
				BigInteger EncryptedMessage2 = publickey2.encrypt(m);
				String em2 = fromBigInteger(EncryptedMessage2);
				MessageDecryption Decrypt2 = new MessageDecryption(privatekey2_Scen3,publickey2_Scen3,upperBound);
				BigInteger DecryptedMessage2 = Decrypt2.decrypt(EncryptedMessage2); 
				String Dem2 = fromBigInteger(DecryptedMessage2);
				System.out.printf("The  Encrypted message for B is : %s \n",em2);
				System.out.printf("The B receiver decrypts the message as : %s \n",Dem2);
				System.out.println("Everything goes as normal!");
			}
			else {
				System.out.println("Wrong Input, try again");
				
				
			}
			
			
			}while (Scenario!=1 && Scenario!=2 && Scenario!=3);
			//while (Scenario==1 || Scenario==2 || Scenario==3);
			
			}
		}


	public static BigInteger StringToInt(String m){
		return new BigInteger(m.getBytes());
		
	}
	
	public static String fromBigInteger(BigInteger bar)
	{
	    return new String(bar.toByteArray());
	}

	
}
