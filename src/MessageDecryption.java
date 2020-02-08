import java.math.BigInteger;

public class MessageDecryption  extends Paillier_Cryptosystem{
	private  Privatekey privatekey;                // Einai final kanonika
	private  Publickey  publickey;					// kai auto
	private static BigInteger upperBound;
	
	
	MessageDecryption(Privatekey privatekey, Publickey publickey, BigInteger upperBound) {
        this.privatekey = privatekey;
        this.publickey = publickey;
        this.upperBound = upperBound;
    }
	 public  Privatekey getPrivatekey() {
	        return privatekey;
	    }

	    public  Publickey getPublickey() {
	        return publickey;
	    }
   public static BigInteger getupperBound(){
	   return upperBound;
   }
	    /**
	     * Decrypts the given ciphertext.
	     *
	     * @param c The ciphertext that should be decrypted.
	     * @return The corresponding plaintext. If an upper bound was given to {@link KeyPairBuilder},
	     * the result can also be negative. See {@link KeyPairBuilder#upperBound(BigInteger)} for details.
	     */
	    public  BigInteger decrypt(BigInteger c) {          //Auto kanonika einai final
	    	
	        BigInteger n = publickey.getN();
	        BigInteger nSquare = publickey.getnSquared();
	        BigInteger lambda = privatekey.getLambda();
	      //  System.out.println("Lambda is :" +lambda);              // Na THMITHW NA TO SVISW META
	        BigInteger u = privatekey.getem();

	        BigInteger p = c.modPow(lambda, nSquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);

	        if (upperBound != null && p.compareTo(upperBound) > 0) {
	            p = p.subtract(n);
	        }

	        return p;
	    }
	
	
}
