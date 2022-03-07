package com.zdcode;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;

public class BaseApp extends AbstractJni {
    protected final AndroidEmulator emulator;
    protected final VM vm;
    protected final Module module;
    protected BaseApp(String processName, String apkPath, String soPath){
        // 创建模拟器实例,进程名建议依照实际进程名填写，可以规避针对进程名的校验
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName(processName).build();
        // 获取模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建Android虚拟机,传入APK，Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM(new File(apkPath));
        //
        //vm = emulator.createDalvikVM();

        // 加载目标SO
        DalvikModule dm = vm.loadLibrary(new File(soPath), true); // 加载so到虚拟内存
        //获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        vm.setJni(this); // 设置JNI
        vm.setVerbose(true); // 打印日志

        dm.callJNI_OnLoad(emulator); // 调用JNI OnLoad
    }

    protected void breakPoint(long position){
        emulator.attach().addBreakPoint(position);
    }

    protected void hook(Module module, long offset, BreakPointCallback callback){
        emulator.attach().addBreakPoint(module, offset, callback);
    }

    protected void trace(long begin, long end){
        String traceFile = "target/traceCode.txt";
        PrintStream traceStream = null;
        try {
            traceStream = new PrintStream(new FileOutputStream(traceFile), true);
            emulator.traceCode(begin, end).setRedirect(traceStream);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}
