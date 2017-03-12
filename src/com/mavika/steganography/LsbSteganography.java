package com.mavika.steganography;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Steganography is one of the most powerful techniques to
 * conceal the existence of hidden secret data inside a cover
 * object. Images are the most popular cover objects for Steganography.
 * <p>
 * The Least Significant Bit (LSB) is one of the main techniques
 * in spatial domain image steganography.
 * <p>
 * This program is implementation of LSB stenography algorithm to hide a secret message inside a cover image
 */
public class LsbSteganography {

    /**
     * Default password to encrypt and decrypt
     */
    private static final String DEFAULT_PASSWORD = "password";

    /**
     * Java property name that defines the line separator based on the underlying platform
     */
    private static final String LINE_SEPARATOR_PROPERTY = "line.separator";

    private enum COMMAND {
        ENCODE,
        DECODE;
    }

    /**
     * The main entry method of the java program
     *
     * @param args the command line arguments
     * @throws Exception if any error occurs
     * @see #printUsage for detailed description of each command line argument
     */
    public static void main(String[] args) throws Exception {
        AESCrypt aesCrypt = new AESCrypt();
        /**
         * Validate the input arguments
         * @see #printUsage(Exception) to have a detailed understanding of all the supported arguments
         */
        if (args.length != 2 && args.length != 3) {
            printUsage(new IllegalArgumentException("Invalid command line arguments"));
        } else if (args.length == 2 && !COMMAND.DECODE.name().equals(args[0])) {
            printUsage(new IllegalArgumentException("Invalid command line arguments"));
        } else if (args.length == 3 && !COMMAND.ENCODE.name().equals(args[0])) {
            printUsage(new IllegalArgumentException("Invalid command line arguments"));
        }
        // everything is valid now do the processing
        if (COMMAND.ENCODE.name().equals(args[0])) {
            String stenoImagePath = encode(args, aesCrypt);
            // for verification decode the message
            String decodedMessage = decode(stenoImagePath, aesCrypt);
            if (decodedMessage.equals(args[2])) {
                System.out.println(String.format("Results are validated, decoded message equals to encoded message equals to %s", args[2]));
            }
        } else {
            decode(args[1], aesCrypt);
        }
    }

    /**
     * Encode a message in a cover image
     *
     * @param args     the command line arguments
     * @param aesCrypt {@link AESCrypt} object to encrypt the encoded message
     * @return the encoded image path
     * @throws Exception if any error occurs
     */
    private static String encode(String[] args, AESCrypt aesCrypt) throws Exception {
        // cover image path
        String imagePath = args[1];
        File imageFile = new File(imagePath);
        // read the cover image from file object
        BufferedImage coverImage = ImageIO.read(imageFile);
        // length of message to be encoded
        String encryptedMessage = aesCrypt.encrypt(args[2], DEFAULT_PASSWORD);
        int messageLength = encryptedMessage.length();
        String message = "!encoded!" + messageLength + "!" + encryptedMessage;

        messageLength = message.length();
        int[] twoBitMessage = new int[4 * messageLength];
        char currentCharacter;
        for (int i = 0; i < messageLength; i++) {
            currentCharacter = message.charAt(i);
            twoBitMessage[4 * i + 0] = (currentCharacter >> 6) & 0x3;
            twoBitMessage[4 * i + 1] = (currentCharacter >> 4) & 0x3;
            twoBitMessage[4 * i + 2] = (currentCharacter >> 2) & 0x3;
            twoBitMessage[4 * i + 3] = (currentCharacter) & 0x3;
        }
        // the output steno image
        BufferedImage output = ImageIO.read(imageFile);
        int pixel, pixOut, count = 0;
        loop:
        for (int i = 0; i < coverImage.getWidth(); i++) {
            for (int j = 0; j < coverImage.getHeight(); j++) {
                if (count < 4 * messageLength) {
                    pixel = coverImage.getRGB(i, j);
                    pixOut = (pixel & 0xFFFFFFFC) | twoBitMessage[count++];
                    output.setRGB(i, j, pixOut);
                } else {
                    break loop;
                }
            }
        }
        String outputFileName = String.format("%s-%d.png", "steno", System.currentTimeMillis());
        File outputFile = new File(imageFile.getParent(), outputFileName);
        // write the output file
        ImageIO.write(output, "png", outputFile);
        return outputFile.getAbsolutePath();
    }

    /**
     * Deocde a message from the steno image
     *
     * @param stenoImagePath the steno image path
     * @param aesCrypt       {@link AESCrypt} object to decrypt the encoded message
     * @return the decoded message from the steno image
     * @throws Exception if any error occurs
     */
    private static String decode(String stenoImagePath, AESCrypt aesCrypt) throws Exception {
        File imageFile = new File(stenoImagePath);
        BufferedImage stenoImage = ImageIO.read(imageFile);
        if (!isEncoded(stenoImage)) {
            System.out.println("No data is encoded in the steno image");
            System.exit(0);
        }
        int msgLength = getEncodedLength(stenoImage);
        StringBuffer decodedMsg = new StringBuffer();
        Deque<Integer> listChar = new ArrayDeque<Integer>();
        int pixel, temp, charOut, ignore = 0, count = 0;
        loop:
        for (int i = 0; i < stenoImage.getWidth(); i++) {
            for (int j = 0; j < stenoImage.getHeight(); j++) {
                if (ignore < 36 + 4 * (String.valueOf(msgLength).length() + 1)) {
                    ignore++;
                    continue;
                }

                if (count++ == 4 * msgLength) {
                    break loop;
                }
                pixel = stenoImage.getRGB(i, j);
                temp = pixel & 0x03;

                listChar.add(temp);

                if (listChar.size() >= 4) {
                    charOut = (listChar.pop() << 6) | (listChar.pop() << 4) | (listChar.pop() << 2) | listChar.pop();
                    decodedMsg.append((char) charOut);
                }
            }
        }
        String outputMsg = new String(decodedMsg);
        String decryptedMessage = aesCrypt.decrypt(outputMsg, DEFAULT_PASSWORD);
        return decryptedMessage;
    }

    /**
     * Check that message is encoded in the image
     *
     * @param input the input image
     * @return <CODE>true</CODE> is message is encoded otherwise <CODE>false</CODE>
     */
    private static boolean isEncoded(BufferedImage input) {
        StringBuffer decodedMsg = new StringBuffer();
        Deque<Integer> listChar = new ArrayDeque<Integer>();

        int pixel, temp, charOut, count = 0;
        loop:
        for (int i = 0; i < input.getWidth(); i++) {
            for (int j = 0; j < input.getHeight(); j++, count++) {

                if (count == 45) {
                    break loop;
                }
                pixel = input.getRGB(i, j);
                temp = pixel & 0x03;

                listChar.add(temp);

                if (listChar.size() >= 4) {
                    charOut = (listChar.pop() << 6) | (listChar.pop() << 4) | (listChar.pop() << 2) | listChar.pop();
                    decodedMsg.append((char) charOut);
                    count++;
                }
            }
        }
        String check = new String(decodedMsg);
        if (check.compareTo("!encoded!") == 0) {
            return true;
        }
        return false;
    }

    /**
     * Get the encoded length of the message in the steno image
     *
     * @param input the steno {@link BufferedImage} object
     * @return the message length
     */
    private static int getEncodedLength(BufferedImage input) {

        StringBuffer decodedMsg = new StringBuffer();
        Deque<Integer> listChar = new ArrayDeque<Integer>();

        int pixel, temp, charOut, count = 0;
        loop:
        for (int i = 0; i < input.getWidth(); i++) {
            for (int j = 0; j < input.getHeight(); j++) {
                if (count < 36) {
                    count++;
                    continue;
                }

                pixel = input.getRGB(i, j);
                temp = pixel & 0x03;

                listChar.add(temp);

                if (listChar.size() >= 4) {
                    charOut = (listChar.pop() << 6) | (listChar.pop() << 4) | (listChar.pop() << 2) | listChar.pop();
                    if ((char) charOut == '!') {
                        break loop;
                    } else {
                        decodedMsg.append((char) charOut);
                    }
                }
            }

        }

        String length = new String(decodedMsg);

        return Integer.parseInt(length);
    }

    /**
     * Print the usage information and exit the program.
     *
     * @param ex the optional exception that is the cause of this invocation
     * @throws Exception The optional exception that is the cause of this invocation
     */
    private static void printUsage(Exception ex) throws Exception {
        StringBuffer buffer = new StringBuffer();
        buffer.append("########### USAGE INFORMATION ##############");
        buffer.append(System.getProperty(LINE_SEPARATOR_PROPERTY));
        buffer.append("java <main class name> arg1 arg2 arg3");
        buffer.append(System.getProperty(LINE_SEPARATOR_PROPERTY));
        buffer.append("  - arg1: The command can be ENCODE or DECODE");
        buffer.append(System.getProperty(LINE_SEPARATOR_PROPERTY));
        buffer.append("  - arg2: The path to cover image or steno image, depending on the command");
        buffer.append(System.getProperty(LINE_SEPARATOR_PROPERTY));
        buffer.append("  - arg3: Optional message to encode, if command is ENCODE. Omit this argument if command is DECODE");
        buffer.append(System.getProperty(LINE_SEPARATOR_PROPERTY));
        buffer.append("############################################");
        buffer.append(System.getProperty(LINE_SEPARATOR_PROPERTY));
        System.out.println(buffer.toString());
        if (ex != null) {
            throw ex;
        }
        System.exit(1);
    }
}
