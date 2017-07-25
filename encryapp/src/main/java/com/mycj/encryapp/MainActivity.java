package com.mycj.encryapp;

import android.support.design.widget.TextInputEditText;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.android.song.encryptionlib.AESUtils;
import com.android.song.encryptionlib.Base64Utils;
import com.android.song.encryptionlib.DESUtils;
import com.android.song.encryptionlib.HexUtil;
import com.android.song.encryptionlib.MD5Utils;
import com.android.song.encryptionlib.SHAUtils;

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

    }

    //----------------------------- AES 的加密和解密 ------------------------------------
    public void AESEncrypt(View view){
        String str = etCode.getText().toString();
        if(TextUtils.isEmpty(str)){
            return ;
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
        tvEncryptResult.setText(str);
    }

    //----------------------------- DES 的加密和解密 -------------------------------------
    public void DESEncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
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
        if(generateDESKey == null){
            return ;
        }
        String s = tvEncryptResult.getText().toString();
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

    }

    public void MD5Decrypt(View view){
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

    }

    public void RSADecrypt(View view){

    }

    //------------------------------- SHA 的加密和解密 ----------------------------------------
    public void SHAEncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }

        String encrypt = SHAUtils.encrypt(s);
        tvEncryptResult.setText(encrypt);
    }

    public void SHADecrypt(View view){

    }

    //-------------------------------- TDES 的加密和解密 ---------------------------------------
    public void TDESEncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
    }

    public void TDESDecrypt(View view){

    }

    //-------------------------------- XOR 的加密和解密 ----------------------------------------
    public void XOREncrypt(View view){
        String s = etCode.getText().toString();
        if(TextUtils.isEmpty(s)){
            return ;
        }
    }

    public void XORDecrypt(View view){

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
