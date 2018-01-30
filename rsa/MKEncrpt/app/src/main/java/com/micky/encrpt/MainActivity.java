package com.micky.encrpt;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import com.micky.encrpt.utils.RSAUtils;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            RSAUtils rsaUtils = new RSAUtils();
            rsaUtils.setPrivateKey("MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJQnZtjICoMCwzcZnif3t0fW4hyLqaOGLVfEX/6tQa+wCJq6LI9B7SnCzITsuX3YbkmIo96znWBbL7o7XF/p190TSulFDYyWNnNmvqC8L/0ZzARuRBEepF8IIFtlH013R34WBTsRl0FOr5WAwqFSe4crMCi3ktCuQdM7xGnIZCzVAgMBAAECgYA9uLiRIa23bOQ1RVftYLcbl7s1lz3CIXkscmRnrniKH/VFuMAtopKSblRUIGcatZskyWcztXKgHP0iQe63Cq3iCn1qYpVEp3QBONAoO+qrkL80XndYOuG1El8nIvg7bvR2DChkzWSfZq5OOfE5bxmva3xyhgvBnhSH10+ZI32QgQJBANOp0Z/Jb5coumT/mVpcT+/MsqxxhYYsCu3Y2u5lT2+wl78XDzz2sGnjeGfIXjXwqUl3x6pVWZ2Ry0Tzbnd1KGECQQCzL/gOlV2evm5C0FsQhrYpTj9kYZ7XydsEU87d7XRuaRZb5UhruL1rMwmog7bu8dAsCacFqVUuULGtB8qFcYj1AkEAuMRAGgTkZYaHF41L1+ZHXWRKAGBkl5gwvimUC5Dig/QasxO1GJmbrAOGYso0+08m59worpcs0HCpiXoazyq1YQJAba1k1fhS74F8F+VUeA8cnLfKUXT3NvnU1xc9PdXEOHiWOPVkmJrhRiZdOQo2BJd6ZhoaY3q8Krc1qcVlDrzpqQJBAJwEs0iJRc6uYnUu7LmxxReKdgOH4oDXURPaIRd55GGWihcT+x59vSqQo6/QUpk/wFvNY35RwsQ6Vuttx6KtYyQ=");
            rsaUtils.setPublicKey("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUJ2bYyAqDAsM3GZ4n97dH1uIci6mjhi1XxF/+rUGvsAiauiyPQe0pwsyE7Ll92G5JiKPes51gWy+6O1xf6dfdE0rpRQ2MljZzZr6gvC/9GcwEbkQRHqRfCCBbZR9Nd0d+FgU7EZdBTq+VgMKhUnuHKzAot5LQrkHTO8RpyGQs1QIDAQAB");
            String encryptStr = rsaUtils.encryptByPublicKey("DDDDafda#$@@$", rsaUtils.getPublicKey());
            System.out.println("##" + encryptStr + "##");
            String decriptStr = rsaUtils.decryptByPrivateKey(encryptStr, rsaUtils.getPrivateKey());
            System.out.println(decriptStr);

            encryptStr = "BaUv1mZwzu8lC1KSGWrZt6b1+oCnpTIF28EUicvrvbBqbzGN+TyDtVtVHjMKc2M4h32tVH7XwdEQrpDPVOdqXAYnb0Lafqxu/P9DGdjYuj3quV8m35FauP7MLGext2RA4WrwUpnCSqMaVzoELYcG8JS54NRKxNG0a14/pnUoCNs=";
            decriptStr = rsaUtils.decryptByPrivateKey(encryptStr, rsaUtils.getPrivateKey());
            System.out.println(decriptStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
