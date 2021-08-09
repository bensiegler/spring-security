package org.springframework.security.web.authentication.twofa.services;

import java.nio.ByteBuffer;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.core.codec.Decoder;
import org.springframework.util.Assert;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.TwoFactorPreference;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.BitSet;
import org.apache.commons.codec.binary.Base32;

public class TotpService {

	private final static int DEFAULT_CODE_LENGTH = 6;
	private int codeLength = DEFAULT_CODE_LENGTH;

	public TotpService() {
	}

	public TotpService(int codeLength) {
		this.codeLength = codeLength;
	}

	public void confirmCode(TwoFactorPreference preference, String codeToCheck) {
		Assert.isTrue(preference.isKey(),
				"non-key 2FA preference was passed to TotpService's confirmCode()");

		codeToCheck = codeToCheck.trim();
		String secret = preference.getData();
		long currentInterval = System.currentTimeMillis() / 30000;

		if(generateCode(secret, currentInterval).equals(codeToCheck)) {
			return;
		}else{
			if(generateCode(secret, currentInterval - 1).equals(codeToCheck)) {
				return;
			}
			if(generateCode(secret, currentInterval - 2).equals(codeToCheck)) {
				return;
			}
		}
		throw new BadCredentialsException("code was incorrect!");
	}

	//TODO figure this shit out
	public String generateCode(String secret, long interval) {
		byte[] hash = generateHash(secret, interval);
		long partialHash = 0;
		int offset = hash[hash.length - 1] & 0xF;

		for (int i = 0; i < 4; ++i) {
			partialHash <<= 8;
			partialHash |= (hash[offset + i] & 0xFF);
		}

		partialHash &= 0x7FFFFFFF;
		partialHash %= Math.pow(10, codeLength);
		return String.format("%0" + 6 + "d", partialHash);
	}

	public byte[] generateHash(String secret, long interval) {
		try {
			Base32 base32 = new Base32();
			Key key = new SecretKeySpec(base32.decode(secret),"HmacSHA1");
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(key);
			return mac.doFinal(longToBytes(interval));
		}catch (NoSuchAlgorithmException | InvalidKeyException e) {
			//should not happen
			return new byte[1];
		}catch (Exception e) {
			System.out.println(e.getMessage());
			return new byte[1];
		}
	}

	public byte[] longToBytes(long x)  {
		ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
		byteBuffer.putLong(x);
		return byteBuffer.array();
	}

	public int bytesToInt(byte[] bytes) {
		ByteBuffer buffer = ByteBuffer.wrap(bytes);
		return buffer.getInt();
	}
}
