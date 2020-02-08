import java.math.BigInteger;
public class Privatekey extends Paillier_Cryptosystem{
	  
	private static BigInteger lambda;
	    private static  BigInteger em;

	    Privatekey(BigInteger lambda, BigInteger em) {
	       this.lambda = lambda;

	        this.em = em;
	    }

	    public static BigInteger getLambda() {
	        return lambda;
	    }

	    public static BigInteger getem() {
	        return em;
	    }
	
}
