package com.systemsltd.common.security;

import com.systemsltd.common.util.CipherUtils;
import com.systemsltd.common.cache.GlobalCacheHelper;

public class GenerateHash
{
    public static byte[] generateResponseHash(final byte[] data, final byte[] key) {
        final String hashTechnique = GlobalCacheHelper.readFromCache("ConfigCache", "HASHING_TECH_KEY");
        final String symmetricAlgo = GlobalCacheHelper.readFromCache("ConfigCache", "SYMMETRIC_ALGORITHM");
        try {
            final byte[] gerneratedHash = CipherUtils.generateHash(data, hashTechnique);
            final byte[] encryptedResponse = CipherUtils.encrypt(gerneratedHash, symmetricAlgo, key, null);
            return encryptedResponse;
        }
        catch (Exception ex) {
            return null;
        }
    }
}
