import java.util.Scanner;

public class AES {


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean firstCondition = true;
        String keyinput = "";
        System.out.println("Is the Key 1. ASCII(16) or 2. Hex(32)?");
        boolean typekey = true;
        if (scanner.nextLine().equals("2")) {
            typekey = false;
        } else {
            typekey = true;
        }
        while (firstCondition) {
            keyinput = getKey(scanner);
            if (!keyinput.equals(" ")) {
                firstCondition = false;
            }
        }
        String keybin = "";
        if (!typekey) {
            keybin = hexToBin(keyinput);
        } else {
            keybin = ACII_to_Bin(keyinput);
        }
        String[] keys = KeyGen(keybin);
        System.out.println("Enter the plaintext: ");
        String plaintext = scanner.nextLine();
        plaintext = ACII_to_Bin(plaintext);

        String Encrypted_msg = Encrypt_follow(plaintext, keys);
        System.out.println("Encrypted Text (ASCII): " + Bin_to_ASCII(Encrypted_msg));
        System.out.println("Encrypted Text (Binary): " + Encrypted_msg);
        System.out.println("Encrypted Text (Hexadecimal): " + binaryToHex(Encrypted_msg));

        String DecryptedtextWithoutPadding = Bin_to_ASCII(decrypt_follow(Encrypted_msg, keys));
        int indexOfpad = DecryptedtextWithoutPadding.indexOf('*');
        if (indexOfpad != -1) {
            DecryptedtextWithoutPadding = DecryptedtextWithoutPadding.substring(0, indexOfpad);
        }
        System.out.println("Decrypted Text (ASCII): " + DecryptedtextWithoutPadding);
        System.out.println("Decrypted Text (Binary): " + decrypt_follow(Encrypted_msg, keys));
        System.out.println("Decrypted Text (Hexadecimal): " + binaryToHex(decrypt_follow(Encrypted_msg, keys)));

        scanner.close();
    }

    public static String Encryption(String M, String[] Keys) {
        M = xorString(M, Keys[0]);
        for (int round = 1; round < 11; round++) {
            String SBoxResult = "";
            for (int i = 0; i < 16; i++) {
                String part = M.substring(i * 8, (i + 1) * 8);
                int row = Integer.parseInt(part.substring(0, 4), 2);
                int col = Integer.parseInt(part.substring(4, 8), 2);
                String numFromBox = Integer.toBinaryString(SBoxes[row][col]);
                numFromBox = String.format("%8s", numFromBox).replace(' ', '0');
                SBoxResult += numFromBox;
            }

            String[][] matrix = messageToMatrix(SBoxResult);
            matrix = shiftRows(matrix);

            if (round != 10) {
                matrix = Mix_Col(matrix);
            }

            M = matrixToMessage(matrix);
            M = xorString(M, Keys[round]);
        }
        return M;
    }

    public static String Decryption(String C, String[] Keys) {


        C = xorString(C, Keys[10]);  // Start with round 10 key

        for (int round = 9; round >= 0; round--) {
            String[][] Matrix = messageToMatrix(C);
            Matrix = invShiftRows(Matrix);
            C = matrixToMessage(Matrix);
            C = invSubBytes(C);
            C = xorString(C, Keys[round]);
            Matrix = messageToMatrix(C);
            if (round != 0) {
                Matrix = invMix_Col(Matrix);
            }
            C = matrixToMessage(Matrix);
        }

        return C;
    }




    public static String invSubBytes(String M) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < 16; i ++) {
            String part = M.substring(i * 8, (i + 1) * 8);
            int row = Integer.parseInt(part.substring(0, 4), 2);
            int col = Integer.parseInt(part.substring(4, 8), 2);
            String numFromBox = Integer.toBinaryString(invSBox[row][col]);
            numFromBox = String.format("%8s", numFromBox).replace(' ', '0');
            result.append(numFromBox);
        }
        return result.toString();
    }

    public static String[][] Mix_Col(String[][] state) {
        String[][] result = new String[4][4];
        String[][] matrix = {
                { "00000010", "00000011", "00000001", "00000001" },
                { "00000001", "00000010", "00000011", "00000001" },
                { "00000001", "00000001", "00000010", "00000011" },
                { "00000011", "00000001", "00000001", "00000010" }
        };

        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                result[row][col] = "00000000";

                for (int i = 0; i < 4; i++) {
                    String a = matrix[row][i];
                    String b = state[i][col];
                    String product = multiplyHex(a, b);
                    result[row][col] = xorString(result[row][col], product);
                }
            }
        }

        return result;
    }

    public static String[][] invMix_Col(String[][] state) {
        String[][] result = new String[4][4];
        String[][] matrix = {
                { "00001110", "00001011", "00001101", "00001001" },
                { "00001001", "00001110", "00001011", "00001101" },
                { "00001101", "00001001", "00001110", "00001011" },
                { "00001011", "00001101", "00001001", "00001110" }
        };

        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                result[row][col] = "00000000";

                for (int i = 0; i < 4; i++) {
                    String a = matrix[row][i];
                    String b = state[i][col];
                    String product = multiplyHex(a, b);
                    result[row][col] = xorString(result[row][col], product);
                }
            }
        }

        return result;
    }


    public static String multiplyHex(String a, String b){
        String result ="";
        if(a.equals("00000010")){
            if(b.charAt(0) == '0'){
                result = LEFT_SHIFT_BY_1(b,1);
            }else{
                result = xorString(LEFT_SHIFT_BY_1(b,1),"00011011");
            }
        }
        else if(a.equals("00000011")){
            result = xorString(multiplyHex("00000010",b),b);
        }
        else if(a.equals("00001001")){
            result = multiplyHex("00000010", b);
            result = multiplyHex("00000010", result);
            result = multiplyHex("00000010", result);
            result = xorString(result, b);
        }
        else if(a.equals("00001011")){
            result = multiplyHex("00000010", b);
            result = multiplyHex("00000010", result);
            result = xorString(result, b);
            result = multiplyHex("00000010", result);
            result = xorString(result, b);
        }
        else if(a.equals("00001101")){
            result = multiplyHex("00000010", b);
            result = xorString(result, b);
            result = multiplyHex("00000010", result);
            result = multiplyHex("00000010", result);
            result = xorString(result, b);
        }
        else if(a.equals("00001110")){
            result = multiplyHex("00000010", b);
            result = xorString(result, b);
            result = multiplyHex("00000010", result);
            result = xorString(result, b);
            result = multiplyHex("00000010", result);
        }
        else{
            result = b;
        }
        return result;
    }

    public static String LEFT_SHIFT_BY_1(String key, int num) {
        char[] keyArray = key.toCharArray();

        for (int i = 0; i < num; i++) {
            for (int j = 0; j < keyArray.length - 1; j++) {
                keyArray[j] = keyArray[j + 1];
            }
            keyArray[keyArray.length - 1] = '0';
        }

        return new String(keyArray);
    }





    public static String xorString(String a, String b){
        String ans = "";
        for (int i = 0; i < a.length(); i++)
        {
            if (a.charAt(i) == b.charAt(i))
                ans += "0";
            else
                ans += "1";
        }
        return ans;
    }

    public static String[] KeyGen(String input){
        String[] FinalKeys = new String[11];
        String[] Words = new String[44];
        FinalKeys[0] = input;
        for(int j = 0; j<4;j++){
            Words[j] = input.substring(j*32,(j+1)*32);
        }
        for(int i = 1; i<11;i++){
            Words[4*i] = xorString(Words[4*(i-1)],G_fun(Words[4*i-1],i));
            for(int z =1;z<4;z++){
                Words[4*i+z] = xorString(Words[4*i+z-1],Words[4*(i-1)+z]);
            }
            FinalKeys[i] = Words[i*4]+Words[i*4+1]+Words[i*4+2]+Words[i*4+3];
        }
        return FinalKeys;

    }

    public static String G_fun(String Word,int roundNum){
        String shiftedW = leftshift(Word, 8);
        String SBoxResult = "";
        for (int k = 0; k < 4; k++) {
            String part = shiftedW.substring(k * 8, (k + 1) * 8);
            int row = Integer.parseInt(part.substring(0, 4), 2);
            int col = Integer.parseInt(part.substring(4, 8), 2);
            String numFromBox = Integer.toBinaryString(SBoxes[row][col]);

            numFromBox = String.format("%8s", numFromBox).replace(' ', '0');
            if(k == 0){
                numFromBox = xorString(numFromBox, roundConstants[roundNum-1]);
            }
            SBoxResult += numFromBox;
        }
        return SBoxResult;
    }



    public static String leftshift(String key, int num) {
        char[] keyArray = key.toCharArray();

        for (int i = 0; i < num; i++) {
            char first = keyArray[0];
            for (int j = 0; j < keyArray.length - 1; j++) {
                keyArray[j] = keyArray[j + 1];
            }
            keyArray[keyArray.length - 1] = first;
        }

        return new String(keyArray);
    }



    public static String[][] messageToMatrix(String M) {
        String[][] matrix = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                matrix[j][i] = M.substring((i * 4 + j) * 8, (i * 4 + j + 1) * 8);
            }
        }
        return matrix;
    }

    public static String matrixToMessage(String[][] matrix) {
        String message = "";
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                message+=(matrix[j][i]);
            }
        }
        return message;
    }



    public static String[][] shiftRows(String[][] matrix) {
        String[][] shiftedMatrix = new String[4][4];

        shiftedMatrix[0] = matrix[0];

        for (int i = 0; i < 4; i++) {
            shiftedMatrix[1][i] = matrix[1][(i + 1) % 4];
        }

        for (int i = 0; i < 4; i++) {
            shiftedMatrix[2][i] = matrix[2][(i + 2) % 4];
        }

        for (int i = 0; i < 4; i++) {
            shiftedMatrix[3][i] = matrix[3][(i + 3) % 4];
        }

        return shiftedMatrix;
    }

    public static String[][] invShiftRows(String[][] matrix) {
        String[][] shiftedMatrix = new String[4][4];

        shiftedMatrix[0] = matrix[0];

        for (int i = 0; i < 4; i++) {
            shiftedMatrix[1][i] = matrix[1][(i + 3) % 4];
        }

        for (int i = 0; i < 4; i++) {
            shiftedMatrix[2][i] = matrix[2][(i + 2) % 4];
        }

        for (int i = 0; i < 4; i++) {
            shiftedMatrix[3][i] = matrix[3][(i + 1) % 4];
        }

        return shiftedMatrix;
    }




    public static  int[][] SBoxes = {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
    };

    public static  int[][] invSBox = {
            {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
            {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
            {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
            {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
            {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
            {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
            {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
            {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
            {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
            {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
            {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
            {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
            {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
            {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
            {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
    };


    public static String[] roundConstants = {
            "00000001", "00000010", "00000100", "00001000",
            "00010000", "00100000", "01000000", "10000000",
            "00011011", "00110110"
    };

    //function men el ass ely fat

    public static String getKey(Scanner scanner) {
        while (true) {
            System.out.println("Please enter the key:");
            String input = scanner.nextLine();
            if (isValidKey(input)) {
                return input;
            } else {
                System.out.println("Invalid key. Please enter 16 ASCII or 32 hexadecimal characters.");
                return " ";
            }
        }
    }

    public static boolean isValidKey(String key) {
        // Law Assci yeba 8 bs
        if (key.matches("[\\x00-\\x7F]{16}")) {
            return true;
        }
        //law hex 16
        if (key.matches("[0-9A-Fa-f]{32}")) {
            return true;
        }
        return false;
    }


    public static String[] divideIntoBlocks(String plaintext) {
        int blockLength = 128;
        int numOfBlocks = (int) Math.ceil((double) plaintext.length() / blockLength);
        String[] blocks = new String[numOfBlocks];
        int startIndex = 0;
        for (int i = 0; i < numOfBlocks; i++) {
            int endIndex = Math.min(startIndex + blockLength, plaintext.length());
            String block = plaintext.substring(startIndex, endIndex);
            if (block.length() < blockLength) {
                StringBuilder paddedBlock = new StringBuilder(block);
                while (paddedBlock.length() < blockLength) {
                    paddedBlock.append("00101010");
                }
                block = paddedBlock.toString();
            }
            blocks[i] = block;
            startIndex = endIndex;
        }
        return blocks;
    }
    public static String Encrypt_follow(String plaintext, String[] key) {
        StringBuilder encryptedText = new StringBuilder();
        String[] blocks = divideIntoBlocks(plaintext);
        for (String block : blocks) {
            encryptedText.append(Encryption(block, key));
        }
        return encryptedText.toString();
    }

    public static String decrypt_follow(String ciphertext, String[] key) {
        StringBuilder decryptedText = new StringBuilder();
        String[] blocks = divideIntoBlocks(ciphertext);
        for (String block : blocks) {
            decryptedText.append(Decryption(block, key));
        }
        return decryptedText.toString();
    }

    public static String hexToBin(String hex){
        hex = hex.replaceAll("0", "0000");
        hex = hex.replaceAll("1", "0001");
        hex = hex.replaceAll("2", "0010");
        hex = hex.replaceAll("3", "0011");
        hex = hex.replaceAll("4", "0100");
        hex = hex.replaceAll("5", "0101");
        hex = hex.replaceAll("6", "0110");
        hex = hex.replaceAll("7", "0111");
        hex = hex.replaceAll("8", "1000");
        hex = hex.replaceAll("9", "1001");
        hex = hex.replaceAll("A", "1010");
        hex = hex.replaceAll("B", "1011");
        hex = hex.replaceAll("C", "1100");
        hex = hex.replaceAll("D", "1101");
        hex = hex.replaceAll("E", "1110");
        hex = hex.replaceAll("F", "1111");
        return hex;
    }


    public static String binaryToHex(String binaryString) {
        String hexString = "";
        for (int i = 0; i < binaryString.length(); i += 4) {
            String group = binaryString.substring(i, i + 4);
            int decimalValue = Integer.parseInt(group, 2);
            String hexValue = Integer.toHexString(decimalValue).toUpperCase();
            hexString += hexValue;
        }
        return hexString;
    }


    public static String ACII_to_Bin(String asciiString) {
        StringBuilder binaryStringBuilder = new StringBuilder();

        for (int i = 0; i < asciiString.length(); i++) {
            int asciiValue = (int) asciiString.charAt(i);
            String binaryValue = Integer.toBinaryString(asciiValue);
            while (binaryValue.length() < 8) {
                binaryValue = "0" + binaryValue;
            }
            binaryStringBuilder.append(binaryValue);
        }

        return binaryStringBuilder.toString();
    }

    public static String Bin_to_ASCII(String binaryString) {
        StringBuilder asciiStringBuilder = new StringBuilder();

        for (int i = 0; i < binaryString.length(); i += 8) {
            String binaryChunk = binaryString.substring(i, Math.min(i + 8, binaryString.length()));
            int asciiValue = Integer.parseInt(binaryChunk, 2);
            char asciiChar = (char) asciiValue;
            asciiStringBuilder.append(asciiChar);
        }

        return asciiStringBuilder.toString();
    }


}