package com.zdcode;

import com.github.unidbg.*;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.unpack.ElfUnpacker;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.io.FileUtils;

import java.io.*;
import java.util.Arrays;

public class BaseApp extends AbstractJni {
    protected AndroidEmulator emulator;
    protected VM vm;
    protected Module module;
    protected Memory memory;
    protected String soPath;
    protected String processName;
    protected String apkPath;
    protected int sdkVersion;
    protected BaseApp(){
        super();
    }

    protected void dumpSo() {
        final String soPath = this.soPath;
        memory.addModuleListener(new ModuleListener() {
            @Override
            public void onLoaded(Emulator<?> emulator, Module module) {
                try{
                    FileInputStream is = new FileInputStream(new File(soPath));
                    int size = is.available();
                    final byte[] elfBytes = new byte[size];
                    is.read(elfBytes);
                    String soName = soPath.substring(soPath.lastIndexOf("/")+1);
                    if (soName.equals(module.name)) {
                        File outFile = new File(FileUtils.getUserDirectory(), "Desktop/" + soName.substring(0, soName.indexOf(".")) + "_patched.so");
                        new ElfUnpacker(elfBytes, outFile).register(emulator, module);
                    }
                }catch (IOException e){
                    throw new UnsupportedOperationException(e);
                }
            }
        });
    }

    protected void beginInit(){
        // 创建模拟器实例,进程名建议依照实际进程名填写，可以规避针对进程名的校验
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName(processName).build();
        // 获取模拟器的内存操作接口
        memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(19));
        // 创建Android虚拟机,传入APK，Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM(new File(apkPath));
        //
        //vm = emulator.createDalvikVM();
        new AndroidModule(emulator, vm).register(memory);
    }

    protected void endInit(){
        // 加载目标SO
        DalvikModule dm = vm.loadLibrary(new File(soPath), true); // 加载so到虚拟内存
        //获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        vm.setJni(this); // 设置JNI
        vm.setVerbose(true); // 打印日志

        dm.callJNI_OnLoad(emulator); // 调用JNI OnLoad
    }

    @SuppressWarnings("unused")
    protected void breakPoint(long offset){
        emulator.attach().addBreakPoint(module.base + offset);
    }

    @SuppressWarnings("unused")
    protected void hook(long offset, BreakPointCallback callback){
        emulator.attach().addBreakPoint(offset, callback);
    }

    @SuppressWarnings("unused")
    protected void hook(long offset, WrapCallback<?> callback){
        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.wrap(module.base + offset, callback);
    }

    @SuppressWarnings("unused")
    protected TraceHook trace(long begin, long end){
        File dir = new File("target");
        if (!dir.exists()){
            dir.mkdir();
        }
        String traceFile = "target/traceCode.txt";
        PrintStream traceStream = null;
        try {
            traceStream = new PrintStream(new FileOutputStream(traceFile), true);
            TraceHook th = emulator.traceCode(module.base + begin, module.base + end);
            th.setRedirect(traceStream);
            return th;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    @SuppressWarnings("unused")
    protected void patch(long offset, String AssemblyCode, byte[] verifyCode){
        Pointer pointer = UnidbgPointer.pointer(emulator, module.base + offset);
        assert pointer != null;
        byte[] code = pointer.getByteArray(0, 4);
        if (!Arrays.equals(code, verifyCode)) {
            throw new IllegalStateException(Inspector.inspectString(code, "patch32 code=" + Arrays.toString(code)));
        }
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb)) {
            KeystoneEncoded encoded = keystone.assemble(AssemblyCode);
            byte[] patch = encoded.getMachineCode();
            if (patch.length != code.length) {
                throw new IllegalStateException(Inspector.inspectString(patch, "patch32 length=" + patch.length));
            }
            pointer.write(0, patch, 0, patch.length);
        }
    }

    @SuppressWarnings("unused")
    protected void patch(long offset, int patchCode, byte[] verifyCode){
        Pointer pointer = UnidbgPointer.pointer(emulator, module.base + offset);
        assert pointer != null;
        byte[] code = pointer.getByteArray(0, 4);
        if (!Arrays.equals(code, verifyCode)) {
            throw new IllegalStateException(Inspector.inspectString(code, "patch32 code=" + Arrays.toString(code)));
        }
        pointer.setInt(0, patchCode);
    }
}
