import java.math.BigInteger;
import java.util.Random;

public class Publickey extends Paillier_Cryptosystem {
	 private final int bits;
	    private static  BigInteger n;
	    private static BigInteger nSquared;
	    private static BigInteger g;
	  //  private BigInteger p,q;

	/*  public  Publickey(BigInteger p, BigInteger q, BigInteger g, int bits) {
	        
	    	this.p = p;
	        this.q = q;
	        this.g = g;
	        this.bits = bits;
	    }
	    */
	  
	    
	    
	    Publickey(BigInteger n, BigInteger nSquared, BigInteger g, int bits) {    // Einai this.
	        Publickey.n = n;
	        Publickey.nSquared = nSquared;
	        this.bits = bits;
	        Publickey.g = g;
	    }
	    
	  /*  public BigInteger Setn(BigInteger p , BigInteger q){
	    	this.n =p.multiply(q);
	    	 return n;
	    }
	    public BigInteger SetnSquared(BigInteger n){
	    	 return nSquared = n.multiply(n);
	    }  */
	    
	    public int getBits() {
	        return bits;
	    }

	    public static  BigInteger getN() {
	        return n;
	    }

	    public static BigInteger getnSquared() {
	        return nSquared;
	    }

	    public static BigInteger getG() {
	        return  g;
	    }
	
	    public final BigInteger encrypt(BigInteger m) {

	        BigInteger r;
	        do {
	            r = new BigInteger(bits, new Random());
	        } while (r.compareTo(n) >= 0);

	        BigInteger encryptedMessage = g.modPow(m, nSquared);
	        BigInteger x = r.modPow(n, nSquared);

	        encryptedMessage  = encryptedMessage.multiply(x);
	        encryptedMessage  = encryptedMessage.mod(nSquared);

	        return encryptedMessage ;
	    }
	}
