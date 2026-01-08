package cn.anxko.app.svchook;

import androidx.appcompat.app.AppCompatActivity;

import android.content.res.AssetManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import cn.anxko.app.svchook.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    public static final String TAG = "KILL_JAVA";

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;

        String apkPath = this.getPackageResourcePath();
        Log.i(TAG, "apk路径: "+apkPath);
        String originPath = getOriginPath();
        Log.i(TAG, "替换路径: "+originPath);
        System.setProperty("mt.signature.killer.path1", apkPath);
        System.setProperty("mt.signature.killer.path2", originPath);
        System.loadLibrary("svchook");
    }

    private String getOriginPath(){
        File file = new File(this.getFilesDir(), "origin.apk");
        if (!file.exists()){
            AssetManager manager = this.getAssets();
            try (
                    InputStream inputStream = manager.open("origin.apk");
                    FileOutputStream outputStream = new FileOutputStream(file);
            ){
                byte[] buffer = new byte[1024];
                int length;
                while ((length = inputStream.read(buffer)) > 0) {
                    outputStream.write(buffer, 0, length);
                    outputStream.flush();
                }
            }catch (IOException e){
                throw new RuntimeException("文件流错误！", e);
            }
        }
        return file.getAbsolutePath();
    }
}