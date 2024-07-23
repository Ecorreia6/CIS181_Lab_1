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
 * Student Name:
 * Date:
 */

import java.util.*;
import java.io.*;
import java.security.*;

public class SimpleAsymKeyEncryptApp {

	public static void main(String[] args) {

		// Other implementations other than RSA do not work without messing with
		// Eclipse's settings
		PublicKeyEncryption pke1 = new PublicKeyEncryption(PublicKeyEncryption.AlgorithmTypes.RSA);

		// Keyboard input.
		Scanner kbInput = new Scanner(System.in);

		// Used to get the users choice from the
		int choice;

		String bufferData;
		String givingFileName;
		String recievingFileName;
		String nameFile;
		String keyName;
		byte encryptedData[], decryptedData[];
		PublicKey publicK;
		PrivateKey privateK;
		do {
			System.out.println("=======================================================");
			System.out.println("Welcome to the Simple Asymmetric Key Encryption Program");
			System.out.println("=======================================================");

			System.out.println("Please choose from the following options:");
			System.out.println("1. Save my public key to a binary file.");
			System.out.println("2. Save my private key to a binary file.");
			System.out.println("3. Generate a new set of my keys.");
			System.out.println("4. Encrypt using my key");
			System.out.println("5. Decrypt using my key");
			System.out.println("6. Encrypt using a key from a file");
			System.out.println("7. Decrypt using a key from a file");
			System.out.println("8. Quit the program");

			// get the users choice
			choice = kbInput.nextInt();
			kbInput.nextLine();// buffer out the end of line character.
			switch (choice) {
			case 1:
				System.out.println("Please enter the file name you would like to save the public key with");
				recievingFileName = kbInput.nextLine();
				saveByteArrayToFile(pke1.getPublicKeyAsByteArray(), recievingFileName);
				System.out.println("Save Complete");
				break;
			case 2:
				System.out.println("Please enter the file name you would like to save the public key with");
				recievingFileName = kbInput.nextLine();
				saveByteArrayToFile(pke1.getPrivateKeyAsByteArray(), recievingFileName);
				System.out.println("Save Complete");
				break;
			case 3:
				pke1.generateNewPair();
				break;
			case 4:
				System.out.println("Input the file name");
				givingFileName = kbInput.nextLine();
				System.out.println("Input the file name to recieve the encrypted text");
				recievingFileName = kbInput.nextLine();
				bufferData = getTextFileAsString(givingFileName);
				encryptedData = pke1.encrypt(bufferData.getBytes());
				saveByteArrayToFile(encryptedData, recievingFileName);

				System.out.println("Text from " + givingFileName + " has been encrypted using your public key");
				System.out.println("and saved to " + recievingFileName);
				System.out.println("Please press enter to continue.");
				kbInput.nextLine();
				break;
			case 5:
				System.out.println("Input the file name");
				givingFileName = kbInput.next();
				encryptedData = loadByteArrayFromFile(givingFileName);
				decryptedData = pke1.decrypt(encryptedData);

				System.out.println("Decrypted Text:");
				System.out.println(new String(decryptedData));
				System.out.println("Please press enter to continue.");
				kbInput.nextLine();
				break;
			case 6:
				System.out.println("Input the file name");
				givingFileName = kbInput.nextLine();
				System.out.println("Please enter the key name you would like to decrypt the text with");
				keyName = kbInput.nextLine();
				bufferData = getTextFileAsString(givingFileName);
				publicK = pke1.convertBytesToPublicKey(loadByteArrayFromFile(keyName));
				encryptedData = pke1.encrypt(bufferData.getBytes(), publicK);
				saveByteArrayToFile(encryptedData, "SampleDataEncrypted.bin");

				System.out.println("Text from " + givingFileName + " has been encrypted using your public key");
				System.out.println("and saved to SampleDataEncrypted.bin");
				System.out.println("Please press enter to continue.");
				kbInput.nextLine();
				break;
			case 7:
				System.out.println("Please enter the file name you would like to recieve the decrypted text with");
				nameFile = kbInput.nextLine();
				PrintWriter filer;
				System.out.println("Please enter the file name you would like to decrypt");
				givingFileName = kbInput.nextLine();
				System.out.println("Please enter the key name you would like to decrypt the text with");
				keyName = kbInput.nextLine();
				try {
					filer = new PrintWriter(nameFile);

					encryptedData = loadByteArrayFromFile(givingFileName);
					privateK = pke1.convertBytesToPrivateKey(loadByteArrayFromFile(keyName));

					decryptedData = pke1.decrypt(encryptedData, privateK);

					filer.println("Decrypted Text:");
					filer.println(new String(decryptedData));
					filer.println("Please press enter to continue.");
					filer.close();
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				kbInput.nextLine();
				break;
			case 8:

				break;
			default:
				System.out.println("Invalid Choice, press enter to continue.");
				kbInput.nextLine();
			}
		} while (choice != 8);

		System.out.println("Thank you for using this program, good bye!");
	}

	private static void saveByteArrayToFile(byte arrayData[], String fileName) {
		// Just dump the whole thing to a binary file.
		try {
			FileOutputStream fos = new FileOutputStream(fileName);
			fos.write(arrayData);
			fos.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static byte[] loadByteArrayFromFile(String fileName) {
		// Just dump the whole thing to a binary file.
		try {
			FileInputStream fis = new FileInputStream(fileName);
			byte buffer[] = fis.readAllBytes();
			fis.close();

			return buffer;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static String getTextFileAsString(String filename) {
		File f = new File(filename);

		String bufferString = "";

		Scanner fileInput;
		try {
			fileInput = new Scanner(f);

			while (fileInput.hasNext()) {
				bufferString += fileInput.nextLine() + "\n";
			}

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return bufferString;
	}

}