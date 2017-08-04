package com.mycj.encryapp;

import android.support.design.widget.TextInputEditText;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.android.song.encryptionlib.AESUtils;
import com.android.song.encryptionlib.Base64Utils;
import com.android.song.encryptionlib.DESUtils;
import com.android.song.encryptionlib.HexUtil;
import com.android.song.encryptionlib.MD5Utils;
import com.android.song.encryptionlib.RSAUtils;
import com.android.song.encryptionlib.SHAUtils;
import com.android.song.encryptionlib.TDESUtils;
import com.android.song.encryptionlib.XORUtils;

import butterknife.BindView;
import butterknife.ButterKnife;

public class MainActivity extends AppCompatActivity {

    public final static int INDEX_AES       = 0;
    public final static int INDEX_BASE64    = 1;
    public final static int INDEX_DES       = 2;
    public final static int INDEX_MD5       = 3;
    public final static int INDEX_RSA       = 4;
    public final static int INDEX_SHA       = 5;
    public final static int INDEX_TDES      = 6;
    public final static int INDEX_XOR       = 7;

    public int current_decrypt_index;
    //--------------------------------- 解密的 Button ---------------------------------------------

    @BindView(R.id.btn_aes_de)
    Button btnAESDe;

    @BindView(R.id.btn_base_de)
    Button btnBaseDe;

    @BindView(R.id.btn_des_de)
    Button btnDESDe;

    @BindView(R.id.btn_md5_de)
    Button btnMD5De;

    @BindView(R.id.btn_ras_de)
    Button btnRASDe;

    @BindView(R.id.btn_sha_de)
    Button btnShaDe;

    @BindView(R.id.btn_tdes_de)
    Button btnTDESDe;

    @BindView(R.id.btn_xor_de)
    Button btnXORDe;

    //---------------------------------------------------------------------------------------------


    //-------------------------------------- 加密的 Button ----------------------------------------
    @BindView(R.id.btn_aes_en)
    Button btnAESEn;

    @BindView(R.id.btn_base_en)
    Button btnBaseEn;

    @BindView(R.id.btn_des_en)
    Button btnDESEn;

    @BindView(R.id.btn_md5_en)
    Button btnMD5En;

    @BindView(R.id.btn_ras_en)
    Button btnRASEn;

    @BindView(R.id.btn_sha_en)
    Button btnShaEn;

    @BindView(R.id.btn_tdes_en)
    Button btnTDESEn;

    @BindView(R.id.btn_xor_en)
    Button btnXOREn;

    //----------------------------------------------------------------------------------------------

    // 输入框
    @BindView(R.id.et_code)
    TextInputEditText etCode;

    // 解密字符
    @BindView(R.id.tv_decrypt_result)
    TextView tvDecryptResult;

    //加密字符
    @BindView(R.id.tv_encrypt_result)
    TextView tvEncryptResult;

    // 解密按钮的数组
    private Button[] deCryptButtons;
    private byte[] generateKey;
    private byte[] generateDESKey;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);

        deCryptButtons = new Button[]{ btnAESDe, btnBaseDe, btnDESDe, btnMD5De,
                btnRASDe, btnShaDe, btnTDESDe, btnXORDe};

        etCode.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if(TextUtils.isEmpty(s)){   //如果 EditText 的输入为空了，就清空解密结果
                    tvDecryptResult.setText("");
                    tvEncryptResult.setText("");
                }

//                String str = s.toString();
//                int index = str.length() - 1;
//                if(index < 0)
//                    return;
//
//                char c = str.charAt(index);
//                if(isA2F(c) || isZero2Ten(c)){
//
//                }else{
//                    Toast.makeText(MainActivity.this,"请输入十六进制的数0 - F",Toast.LENGTH_SHORT).show();
//                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

    }

    private boolean isZero2Ten(char c){
        if(c >= '0' && c <= '9'){
            return true;
        }
        return false;
    }

    private boolean isA2F(char c){
        if( (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ){
            return true;
        }
        return false;
    }

    private boolean isContainsNonHexString(String s){
        char[] chars = s.toCharArray();
        for(char c : chars){
            if(!(isZero2Ten(c)||isA2F(c))){
                return true;
            }
        }
        return false;
    }

    //----------------------------- AES 的加密和解密 ------------------------------------
    public void AESEncrypt(View view){
        String str = etCode.getText().toString();
        if(TextUtils.isEmpty(str)){
            return ;
        }
        if(isContainsNonHexString(str)){
            Toast.makeText(this,"除了MD5、SHA和Base64之外的加密方法，包含非16进制的数,不能进行加密",Toast.LENGTH_SHORT).show();
            return;
        }
        generateKey = AESUtils.generateKey();
        byte[] data = HexUtil.hexStringToBytes(str);
        byte[] encrypt = AESUtils.encrypt(data, generateKey);
        String s = HexUtil.encodeHexStr(encrypt);
        tvEncryptResult.setText(s);
        current_decrypt_index = INDEX_AES;
        disenableOtherDeEncryptButton();

    }

    public void AESDecrypt(View view){
        String s = tvEncryptResult.getText().toString();
        if(TextUtils.isEmpty(s) || generateKey == null){
            return ;
        }
        byte[] encrypt = HexUtil.hexStringToBytes(s);
        byte[] decrypt = AESUtils.decrypt(encrypt, generateKey);
        String str = HexUtil.encodeHexStr(decrypt);
        tvDecryptResult.setText(str);
    }

    //----------------------------- Base64 的加密和解密 ----------------------------------
    public void BaseEncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
        String str = Base64Utils.encodedStr(s);
        tvEncryptResult.setText(str);
        current_decrypt_index = INDEX_BASE64;
        disenableOtherDeEncryptButton();
    }

    public void BaseDecrypt(View view){
        String s = tvEncryptResult.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
        String str = Base64Utils.decodedStr(s);
        tvDecryptResult.setText(str);
    }

    //----------------------------- DES 的加密和解密 -------------------------------------
    public void DESEncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
        if(isContainsNonHexString(s)){
            Toast.makeText(this,"除了MD5、SHA和Base64之外的加密方法，包含非16进制的数,不能进行加密",Toast.LENGTH_SHORT).show();
            return;
        }
        generateDESKey = DESUtils.generateKey();
        byte[] data = HexUtil.hexStringToBytes(s);
        byte[] encrypt = DESUtils.encrypt(data, generateDESKey);
        String str = HexUtil.encodeHexStr(encrypt);
        tvEncryptResult.setText(str);
        current_decrypt_index = INDEX_DES;
        disenableOtherDeEncryptButton();
    }

    public void DESDecrypt(View view){
        String s = tvEncryptResult.getText().toString();
        if(TextUtils.isEmpty(s) || generateDESKey == null){
            return ;
        }
        byte[] encrypt = HexUtil.hexStringToBytes(s);
        byte[] decrypt = DESUtils.decrypt(encrypt, generateDESKey);
        String str = HexUtil.encodeHexStr(decrypt);
        tvDecryptResult.setText(str);
    }

    //----------------------------- MD5 的加密和解密 -------------------------------------
    public void MD5Encrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
        String str = MD5Utils.encryptStr(s);
        tvEncryptResult.setText(str);
        current_decrypt_index = INDEX_MD5;
        disenableOtherDeEncryptButton();
    }

    public void MD5Decrypt(View view){
        Toast.makeText(this,"这种加密是不可逆的",Toast.LENGTH_SHORT).show();
        String s = tvEncryptResult.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
//        MD5Utils.


    }

    //----------------------------- RSA 的加密和解密 --------------------------------------
    public void RSAEncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
        byte[] data = HexUtil.hexStringToBytes(s);
//        RSAUtils.decryptByPrivateKey();
    }

    public void RSADecrypt(View view){

    }

    //------------------------------- SHA 的加密和解密 ----------------------------------------
    //这种加密不可逆
    public void SHAEncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }

        String encrypt = SHAUtils.encrypt(s);
        tvEncryptResult.setText(encrypt);
        current_decrypt_index = INDEX_SHA;
        disenableOtherDeEncryptButton();
    }

    public void SHADecrypt(View view){
        Toast.makeText(this,"这种加密是不可逆的",Toast.LENGTH_SHORT).show();
    }

    //-------------------------------- TDES 的加密和解密 ---------------------------------------
    public void TDESEncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
        if(isContainsNonHexString(s)){
            Toast.makeText(this,"除了MD5、SHA和Base64之外的加密方法，包含非16进制的数,不能进行加密",Toast.LENGTH_SHORT).show();
            return;
        }
        generateKey = TDESUtils.generateKey();
        byte[] bytes = HexUtil.hexStringToBytes(s);
        byte[] encrypt = TDESUtils.encrypt(bytes, generateKey);
        String str = HexUtil.encodeHexStr(encrypt);
        tvEncryptResult.setText(str);
        current_decrypt_index = INDEX_TDES;
        disenableOtherDeEncryptButton();
    }

    public void TDESDecrypt(View view){
        String s = tvEncryptResult.getText().toString();
        if(TextUtils.isEmpty(s) || generateKey == null)
            return;
        byte[] bytes = HexUtil.hexStringToBytes(s);
        byte[] decrypt = TDESUtils.decrypt(bytes, generateKey);
        String str = HexUtil.encodeHexStr(decrypt);
        tvDecryptResult.setText(str);
    }


    //-------------------------------- XOR 的加密和解密 ----------------------------------------
    public void XOREncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
        if(isContainsNonHexString(s)){
            Toast.makeText(this,"除了MD5、SHA和Base64之外的加密方法，包含非16进制的数,不能进行加密",Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] bytes = HexUtil.hexStringToBytes(s);
        byte[] encrypt = XORUtils.encrypt(bytes);
        String str = HexUtil.encodeHexStr(encrypt);
        tvEncryptResult.setText(str);
        current_decrypt_index = INDEX_XOR;
        disenableOtherDeEncryptButton();
    }

    public void XORDecrypt(View view){
        String s = tvEncryptResult.getText().toString();
        if(TextUtils.isEmpty(s)){
            return;
        }
        byte[] bytes = HexUtil.hexStringToBytes(s);
        byte[] decrypt = XORUtils.decrypt(bytes);
        String str = HexUtil.encodeHexStr(decrypt);
        tvDecryptResult.setText(str);
    }



    /**
     * 其他的按钮不能解密（加密方法只对应一种解密方式）
     */
    public void disenableOtherDeEncryptButton(){
        for(int i = 0; i < 8; i++){
            if(current_decrypt_index == i){
                deCryptButtons[current_decrypt_index].setEnabled(true);
            }else{
                deCryptButtons[i].setEnabled(false);
            }
        }
    }
}
