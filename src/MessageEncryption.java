import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

public class MessageEncryption {
	
	
	private int bits = 512;

    private int certainty = 0;

    private Random rng;

    private BigInteger upperBound;
    private BigInteger n,g,lambda,helper;
    /**
     * Sets the size of the key to be created.
     * <p>
     * The default size is 1024 bits.
     *
     * @param bits The size of the key in bits.
     * @return This instance of KeyPairBuilder for method chaining.
     */
    //public MessageEncryption bits(int bits) {
     //   this.bits = bits;
       // return this;
   // }
   // public int getBits(){
    //	return bits;
   // }
    /**
     * See {@link BigInteger#BigInteger(int, int, Random)} for more details.
     * <p>
     * The default value is 0.
     *
     * @return This instance of KeyPairBuilder for method chaining.
     */
    public MessageEncryption certainty(int certainty) {
        this.certainty = certainty;
        return this;
    }

    /**
     * Sets the random number generator that is used for the generation of
     * internally needed prime numbers.
     * <p>
     * The default is {@link SecureRandom}.
     * <p>
     * <b>Warning:</b>
     * The change of this value affects the security of the whole cryptographic
     * system.
     *
     * @param rng The random number generator that should be used instead of
     *            {@link SecureRandom}.
     * @return This instance of KeyPairBuilder for method chaining.
     */
    public MessageEncryption randomNumberGenerator(Random rng) {
        this.rng = rng;
        return this;
    }

    /**
     * Sets an upper bound that is used for decrypting ciphertexts representing a negative value.
     * <p>
     * In most cases the upper bound should be the same as of the underlying number system -
     * for example {@link Integer#MAX_VALUE}.
     *
     * @param b The upper bound.
     * @return This instance of KeyPairBuilder for method chaining.
     */
    public MessageEncryption upperBound(BigInteger b) {
        this.upperBound = b;
        return this;
    }

    /**
     * Creates a pair of associated public and private keys.
     *
     * @return The pair of associated public and private keys.
     */
    
    public void generateKeyPair(){
    	 if (rng == null) {
             rng = new SecureRandom();
         }
         //Scanner keyboard = new Scanner(System.in);
         BigInteger p, q;
         int length = bits / 2;
         if (certainty > 0) {
             p = new BigInteger(length, certainty, rng);
             q = new BigInteger(length, certainty, rng);
         } else {
             p = BigInteger.probablePrime(length, rng);
             q = BigInteger.probablePrime(length, rng);
         }

         BigInteger n = p.multiply(q);
         BigInteger nSquared = n.multiply(n);

         BigInteger pMinusOne = p.subtract(BigInteger.ONE);
         BigInteger qMinusOne = q.subtract(BigInteger.ONE);

         BigInteger lambda = this.lcm(pMinusOne, qMinusOne);

         BigInteger g;
         BigInteger helper;

         do {
             g = new BigInteger(bits, rng);
             helper = calculateL(g.modPow(lambda, nSquared), n);

         } while (!helper.gcd(n).equals(BigInteger.ONE));
         Publickey publickey = new Publickey(n, nSquared, g, bits);
         Privatekey privatekey = new Privatekey(lambda, helper.modInverse(n));
         BigInteger k = publickey.getN();
         BigInteger O = publickey.getG();
         BigInteger lambd = privatekey.getLambda();
         BigInteger mi = privatekey.getem();
         System.out.printf("The value of N is :%d \n",k);
         System.out.printf("The value of G is :%d \n",O);
         System.out.printf("So the Public key is (%d,%d)\n",k,O);
         System.out.printf("And the Private key is (%d,%d)\n",lambd,mi);
    	
    }
    public BigInteger getN()
    {
    	return n;
    }
    
    public BigInteger getG()
    {
    	return g;
    }
    public BigInteger getL()
    {
    	return lambda;
    }
    public BigInteger getM()
    {
    	return helper;
    }
    
  /*  public MessageDecryption generateKeyPair() {
        if (rng == null) {
            rng = new SecureRandom();
        }
        Scanner keyboard = new Scanner(System.in);
        BigInteger p, q;
        int length = bits / 2;
        if (certainty > 0) {
            p = new BigInteger(length, certainty, rng);
            q = new BigInteger(length, certainty, rng);
        } else {
            p = BigInteger.probablePrime(length, rng);
            q = BigInteger.probablePrime(length, rng);
        }

        BigInteger n = p.multiply(q);
        BigInteger nSquared = n.multiply(n);

        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger qMinusOne = q.subtract(BigInteger.ONE);

        BigInteger lambda = this.lcm(pMinusOne, qMinusOne);

        BigInteger g;
        BigInteger helper;

        do {
            g = new BigInteger(bits, rng);
            helper = calculateL(g.modPow(lambda, nSquared), n);

        } while (!helper.gcd(n).equals(BigInteger.ONE));

        Publickey publickey = new Publickey(n, nSquared, g, bits);
        Privatekey privatekey = new Privatekey(lambda, helper.modInverse(n));
        BigInteger k = publickey.getN();
        BigInteger O = publickey.getG();
        BigInteger lambd = privatekey.getLambda();
        BigInteger mi = privatekey.getem();
        System.out.printf("The value of N is :%d \n",k);
        System.out.printf("The value of G is :%d \n",O);
        System.out.printf("So the Public key is (%d,%d)\n",k,O);
        System.out.printf("And the Private key is (%d,%d)\n",lambd,mi);
       // System.out.println("What's the Message?");
       // BigInteger m = keyboard.nextBigInteger();
       // BigInteger encrypted = publickey.encrypt(m);
       // System.out.print("The Encrypted message is: ");
       // System.out.println(encrypted);
      //  MessageDecryption Decrypt = new MessageDecryption(privatekey, publickey, upperBound);
       // 
// Apo auto to shmeio ginetai h apokwdikopoihsh toy mynymatos
      // BigInteger Decrypted = Decrypt.decrypt(encrypted);
     //  System.out.print("The Decrypted message is: ");
     //  System.out.println(Decrypted);
       return new MessageDecryption(privatekey, publickey, upperBound);
    }
    */

    // TODO separate this somewhere
    private BigInteger calculateL(BigInteger u, BigInteger n) {
        BigInteger result = u.subtract(BigInteger.ONE);
        result = result.divide(n);
        return result;
    }

    // TODO add to own BigInteger extended class
    private BigInteger lcm(BigInteger a, BigInteger b) {
        BigInteger result;
        BigInteger gcd = a.gcd(b);

        result = a.abs().divide(gcd);
        result = result.multiply(b.abs());

        return result;
    }

}
