# PE Loader

> https://github.com/ijiabao/peloader

* 手动 DLL 加载工具, 介绍了PE/DLL的加载和运行原理 (加载后,系统枚举不出DLL映像)
* 注入远程时,支持C库CRT (DLL使用与宿主相同的MSVC版本编译,否则自行解决加载MSVC问题)
* 部分SafeMon会劫持CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, 自行解决



# 免责声明

* 代码仅供学习
* 不可用于商业以及非法目的,使用本代码产生的一切后果, 作者不承担任何责任.



## Injector 原理

按LoadLibrary的逻辑还原可执行映像, 生成一个入口函数, 根据远程地址处理导入函数表和重定位

```c++
void TestInject(HANDLE hProcess, wchar_t* dllfile){
    PELoader loader;
    loader.CreateImage(dllfile);	// 生成欲注入的dll映像
    void* ThreadMain = 0;	// 远程入口点函数地址
    void* remote = loader.Inject(hProcess, "RemoteCRTStartup", &ThreadMain);
    HANDLE hThread = CreateRemoteThread(
        hProcess, 0, 0,
        (LPTHREAD_START_ROUTINE)ThreadMain, 	// 入口点
        (void*)remote, 	// 参数为自已, 在远程对应的hModule
        0, 0);
    // WaitForSingleObject(hThread, -1);    
}                              
```



## Dll 引导原理

将remote_util.h, remote_util.cpp 放在Dll项目内编译即可

```c++
// 导出函数
#if defined(_WIN64)
#pragma comment(linker, "/EXPORT:RemoteCRTStartup=?RemoteCRTStartup@@YAKPEAX@Z,@888") // @@YGKPAX@Z,@8,NONAME
#else
#pragma comment(linker, "/EXPORT:RemoteCRTStartup=?RemoteCRTStartup@@YGKPAX@Z,@888") // @@YGKPAX@Z,@8,NONAME
#endif

// 远程引导函数
DWORD WINAPI RemoteCRTStartup(LPVOID lpThreadParameter){
    HMODULE hModule = (HMODULE)lpThreadParameter; // 传入的参数,实为注入的映像首地址, 参见CreateRemoteThread
    // 注入后,核心Win32API是可以正常使用的(基址不变), 利用核心API再次修复导入表
    if(!FixupImports(hModule)){
		return SafeExit();	// 自删除
	}
    
    // 找到原始Dll入口点
    PIMAGE_NT_HEADERS nth = NTHEADER(hModule);
	*(UINT_PTR*)& DllMainCRTStartup = (UINT_PTR) hModule + nth->OptionalHeader.AddressOfEntryPoint;
    // 调用入口点 DllMain
    DllMainCRTStartup(hModule, DLL_PROCESS_ATTACH,NULL);
    DllMainCRTStartup(hModule, DLL_PROCESS_DETACH,NULL);
}
```





