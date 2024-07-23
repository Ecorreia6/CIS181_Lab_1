/* 
 * Professor/Programmer: Clinton Rogers
 *
 * Any documents, source code, or work you create/modify as a result of this project is the 
 * property of the University of Massachusetts Dartmouth.  This document and any and all source 
 * code cannot be shared with anyone except: University of Massachusetts Dartmouth faculty 
 * (including TA’s), and in a private digital portfolio (public access online is prohibited) 
 * with the intention of applying to jobs and internships. These exceptions are non-transferable. 
 * Failure to comply is, at the very least, an academic infraction that could result in dismissal 
 * from the university. 
 * 
 * Student Name: Evan Correia
 * Date: 1/24/23
 */

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class PublicKeyEncryption {

	public enum AlgorithmTypes{
		DIFFIEHELLMAN,
		RSA,
		DSA,
		RSASSA_PSS,
		EC
	}
	
	private String algorithmName;
	
	private KeyPair keyPair;
	
	private KeyPairGenerator keyPairGenerator;
	//https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html

	private SecureRandom secureRandom;
	//https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html

	public PublicKeyEncryption(AlgorithmTypes choice)
	{
		//https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
		algorithmName = convertEnumAlgorithmToString(choice);

		try {
			keyPairGenerator = KeyPairGenerator.getInstance(algorithmName);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println(algorithmName + " algorithm type not supported! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		

		//Create an instance of SecureRandom
		secureRandom = new SecureRandom();

		//How big should the key be?  Larger number, more secure, longer to process.
		keyPairGenerator.initialize(1024, secureRandom);
		
		generateNewPair();
	}
	
	public void generateNewPair()
	{
		//It's like the name says, it's generates a new pair
		keyPair = keyPairGenerator.generateKeyPair();		
	}
	

	public byte[] encrypt(byte[] dataToBeEncrypted)
	{
		//Calls encrypt, but using the generated public key of this instance.
		return encrypt(dataToBeEncrypted, keyPair.getPublic());
	}
	
	public byte[] encrypt(byte[] dataToBeEncrypted, PublicKey key)
	{
		if(key==null)
		{
			System.out.println("Invalid public key, program quitting");
			System.exit(-1);
		}

		Cipher cipher;
		try {
			
			cipher = Cipher.getInstance(algorithmName);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(dataToBeEncrypted);
			
		}
		catch (NoSuchPaddingException e) {
			e.printStackTrace();
			System.out.println("No Such Padding issue! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		catch (InvalidKeyException e)
		{
			e.printStackTrace();
			System.out.println("No Such Padding issue! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		catch (IllegalBlockSizeException e)
		{
			e.printStackTrace();
			System.out.println("Illegal Block Size Issue! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		catch (BadPaddingException e)
		{
			e.printStackTrace();
			System.out.println("Bad Padding issue! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
			System.out.println(algorithmName + " algorithm type not supported! Program Exiting!");
			System.out.flush();
			System.exit(-2);
		}
		
		//Should be unreachable code.  Either it returns the encrypted data, or it exits the program.
		return null;
	}
	
	public byte[] decrypt(byte[] dataToBeDecrypted)
	{
		return decrypt(dataToBeDecrypted, keyPair.getPrivate());
	}

	public byte[] decrypt(byte[] dataToBeDecrypted, PrivateKey key)
	{

		Cipher cipher;

		try {
			cipher = Cipher.getInstance(algorithmName);
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(dataToBeDecrypted);
		} 
		catch (NoSuchPaddingException e) {
			e.printStackTrace();
			System.out.println("No Such Padding issue! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		catch (InvalidKeyException e)
		{
			e.printStackTrace();
			System.out.println("No Such Padding issue! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		catch (IllegalBlockSizeException e)
		{
			e.printStackTrace();
			System.out.println("Illegal Block Size Issue! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		catch (BadPaddingException e)
		{
			e.printStackTrace();
			System.out.println("Bad Padding issue! Program Exiting!");
			System.out.flush();
			System.exit(-1);
		}
		catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
			System.out.println(algorithmName + " algorithm type not supported! Program Exiting!");
			System.out.flush();
			System.exit(-2);
		}

		//Should be unreachable code.  Either it returns the encrypted data, or it exits the program.
		return null;
	}
	
	public byte[] getPublicKeyAsByteArray()
	{
		return this.keyPair.getPublic().getEncoded();
	}
	
	public byte[] getPrivateKeyAsByteArray()
	{
		return this.keyPair.getPrivate().getEncoded();
	}
	
	public PublicKey convertBytesToPublicKey(byte[] keyAsBytes)
	{
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyAsBytes);
        KeyFactory kf;
		try {
			kf = KeyFactory.getInstance(algorithmName);
	        PublicKey pk = kf.generatePublic(spec);
	        return pk;
	        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public PrivateKey convertBytesToPrivateKey(byte[] keyAsBytes)
	{
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyAsBytes);
        KeyFactory kf;
		try {
			kf = KeyFactory.getInstance(algorithmName);
	        PrivateKey pk = kf.generatePrivate(spec);
	        return pk;
	        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	private String convertEnumAlgorithmToString(AlgorithmTypes a)
	{
		//Because we can't use - and have to use _ instead, it's a special case
		//where we can't rely on toString to do the conversion for us.
		if(a == AlgorithmTypes.RSASSA_PSS)
			return "RSASSA-PSS";
		
		return a.toString();
	}
}


