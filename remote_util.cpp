/*
* @Author: iJiabao <ijiabao@qq.com>
* @Home: https://github.com/ijiabao
*/

#include "remote_util.h"

#define NTHEADER(img) (IMAGE_NT_HEADERS*)((UINT_PTR)img + ((IMAGE_DOS_HEADER*)img)->e_lfanew)

// 注入的Dll首地址，做为HMODULE，但是不可当作HMODULE来用
static void* __image = 0;
static ModuleExtData* __extdata = 0;	// 附加数据


// 修复导入表
int __stdcall FixupImports(void* image);

// 强迫症患者的福音, 释放自已
int __declspec(naked) __stdcall SafeExit(int CodeExit = -8888){
	__asm{
		//push -8888				// 设置ExitThread参数, 即退出值.
		PUSH DWORD PTR [ESP + 4];	// 设置ExitThread参数, 即退出值.(此时正好为传入的参数CodeExit) ;
		PUSH DWORD PTR PostQuitMessage;	// ExitThread执行后返回的地方, 事实上永远也不会返回
		PUSH MEM_RELEASE			// Virtual Free 的三个参数
		PUSH 0
		PUSH DWORD PTR __image;
		PUSH DWORD PTR ExitThread	// 执行VirautlFree后, 返回（调用）ExitThread
		JMP DWORD PTR VirtualFree	// 低版本的VS, dword ptr 是必须的
		retn
	}
}

// 做为注入DLL，此函数才是入口点，也做为RemoteThread；需导出，并在注入端调用 CreateRemoteThread 来执行此函数
// 此函数执行过程与LoadLibrary后的初始化是基本一致的
#if defined(_WIN64)
#pragma comment(linker, "/EXPORT:RemoteCRTStartup=?RemoteCRTStartup@@YAKPEAX@Z,@888") // @@YGKPAX@Z,@8,NONAME
#else
#pragma comment(linker, "/EXPORT:RemoteCRTStartup=?RemoteCRTStartup@@YGKPAX@Z,@888") // @@YGKPAX@Z,@8,NONAME
#endif

/*__declspec(dllexport)*/ // 由上面的linker来指定此函数的导出函数名称
DWORD WINAPI RemoteCRTStartup(LPVOID lpThreadParameter){
	// 参数必须为注入module的首地址
	__image = lpThreadParameter;
	if(!FixupImports(__image)){
		return SafeExit();
	}

	PIMAGE_NT_HEADERS nth = NTHEADER(__image);
	// 附加数据
	__extdata = (ModuleExtData*) ((char*)__image + nth->OptionalHeader.SizeOfImage);

	// 原始Dll入口点
	BOOL(APIENTRY* DllMainCRTStartup)(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) = 0;
	*(UINT_PTR*)& DllMainCRTStartup = (UINT_PTR) __image + nth->OptionalHeader.AddressOfEntryPoint;
	
	// 调用原始入口点,初始化CRT. (如果成功,会自动调用DllMain(), 我们的主体程序放在DllMain运行内)
	DllMainCRTStartup((HMODULE)__image, DLL_PROCESS_ATTACH,NULL);
	
	//TestCRT(0);
	//运行完毕,调用DLL_PROCESS_DETACH
	DllMainCRTStartup((HMODULE)__image, DLL_PROCESS_DETACH,NULL);
	return SafeExit();
}


// 修复导入函数地址表,过程注释参见PELoader::FixupImports
int __stdcall FixupImports(void* image){
	if (!image){
		MessageBox(NULL, L"参数错误!", L"提示信息", MB_OK);
		return 0;
	}

	char* module = (char*)image;	// 便于计算RVA
	
	// 导入表信息
	PIMAGE_NT_HEADERS nth = NTHEADER(module);
	IMAGE_DATA_DIRECTORY dir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!dir.Size) return 1;
	
	// 导入表的游标
	PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR) (module + dir.VirtualAddress);

	while (desc->Characteristics){	// 0 for terminating null import descriptor
		char* dllname = module + desc->Name;
		PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)(module + desc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA) (module + desc->FirstThunk);
		
		HMODULE dll = GetModuleHandleA(dllname);
		if (!dll) dll = LoadLibraryA(dllname);
		if (!dll) {
			MessageBoxA(0, dllname, 0, 0);
			MessageBox(0, L"加载模块时,修复引入表失败!", L"提示信息", MB_OK);
			return 0;
		}
		// 依次获取函数名(序号)，写入对应IAT地址
		while (orig->u1.Function){
			char* func = 0;
			if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)){ //序号 (最高位是1)
				func = (char*)IMAGE_ORDINAL(orig->u1.Ordinal);	// 取低位(半个长度)
			}
			else{ // 名称 （取RVA, 为IMAGE_IMPORT_BY_NAME指针)
				char* addr = module + (UINT_PTR) orig->u1.AddressOfData;
				func = (char*) ((PIMAGE_IMPORT_BY_NAME)addr)->Name;
			}
			*(FARPROC*)& (iat->u1.Function) = GetProcAddress(dll, func);
			orig++; iat++;
		}

		desc++;
	}
	return 1;
}

// 附加数据
ModuleExtData* GetModuleExtData(){
	return __extdata;
}


// 日志相关
#include <io.h>
#include <fcntl.h>
extern "C"{
WINBASEAPI
HWND
APIENTRY
GetConsoleWindow(
    VOID
    );

WINUSERAPI
BOOL
WINAPI
SetLayeredWindowAttributes(
    __in HWND hwnd,
    __in COLORREF crKey,
    __in BYTE bAlpha,
    __in DWORD dwFlags);
};

// 日志安全版
namespace Log 
{

static FILE* __logfile = 0;

int __cdecl out(const wchar_t* format, ...){
	int result = 0;
	va_list ap;
	va_start(ap, format);
	result += vfwprintf(__logfile, format, ap);
	va_end(ap);
	return result;
}

int __cdecl outA(const char* format, ...){
	int result = 0;
	va_list ap;
	va_start(ap, format);
	result += vfprintf(__logfile, format, ap);
	va_end(ap);
	return result;
}


int __stdcall SetConsoleWindow(){
	HWND _hConsole = GetConsoleWindow();
	// 禁止关闭
	EnableMenuItem(::GetSystemMenu(_hConsole, FALSE), SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
	
	// 移到右上角
	int width = GetSystemMetrics(SM_CXSCREEN);
	int height = GetSystemMetrics(SM_CYSCREEN);
	RECT rc;
	GetWindowRect(_hConsole, &rc);
	int w = rc.right - rc.left; int h = rc.bottom - rc.top;
	MoveWindow(_hConsole, width - w, 0, w, h, TRUE);
	
	// 修改透明度
	DWORD _WS_EX_LAYERED = 0x00080000;
	DWORD _LWA_ALPHA = 0x00000002;
	DWORD style = GetWindowLong(_hConsole, GWL_EXSTYLE);
	SetWindowLong(_hConsole, GWL_EXSTYLE, style | _WS_EX_LAYERED);
	SetLayeredWindowAttributes(_hConsole, 0, (255 * 70) / 100, _LWA_ALPHA);
	return 1;
}
	
int __stdcall Init(const wchar_t* file){
	if (file){
		wchar_t path[MAX_PATH];
		swprintf(path, L"%ls\\%ls", GetModuleExtData()->loader_dir, file);
		__logfile = _wfopen(path, L"w+t");
	}
	else{
		AllocConsole();
		SetConsoleWindow();
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		int fd = _open_osfhandle((intptr_t)hOut, _O_TEXT);
		__logfile = _wfdopen(fd, L"w+t");
	}
	if (!__logfile){
		return 0;
	}
	setvbuf(__logfile, NULL, _IONBF, 0);
	_wsetlocale(LC_ALL, L"");
	
	out(L"远程终端测试版V1.0\n\tPowered by ijiabao<ijiabao@qq.com>\n\tstdout:%d\n", _fileno(stdout));
	return 0;
}

int __stdcall Free()
{
	if (GetConsoleWindow()){
		_wsystem(L"pause");
		FreeConsole();	// 会自动关闭osf_handle
		__logfile = 0;	// 否则再次fclose会抛出异常
	}
	if (__logfile){
		fclose(__logfile);
		__logfile = 0;
	}
	
	return 1;
}


};



// 附带远程终端，调试用
ConsoleHlp::ConsoleHlp(){
	AllocConsole();
	_wfreopen(L"CONOUT$", L"w+t", stdout);
	setvbuf(stdout, NULL, _IONBF, 0);
	_wsetlocale(LC_ALL, L"");
	
	wprintf(L"远程终端测试版V1.0\n\tPowered by ijiabao<ijiabao@qq.com>\n\tstdout:%d\n", _fileno(stdout));
	
	_hConsole = GetConsoleWindow();
	
	// 禁止关闭
	//EnableMenuItem(::GetSystemMenu(_hConsole, FALSE), SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
	
	// 移到右上角
	int width = GetSystemMetrics(SM_CXSCREEN);
	int height = GetSystemMetrics(SM_CYSCREEN);
	RECT rc;
	GetWindowRect(_hConsole, &rc);
	int w = rc.right - rc.left; int h = rc.bottom - rc.top;
	MoveWindow(_hConsole, width - w, 0, w, h, TRUE);
	
	// 修改透明度
	DWORD _WS_EX_LAYERED = 0x00080000;
	DWORD _LWA_ALPHA = 0x00000002;
	DWORD style = GetWindowLong(_hConsole, GWL_EXSTYLE);
	SetWindowLong(_hConsole, GWL_EXSTYLE, style | _WS_EX_LAYERED);
	SetLayeredWindowAttributes(_hConsole, 0, (255 * 70) / 100, _LWA_ALPHA);
	
}
ConsoleHlp::~ConsoleHlp(){
	_wsystem(L"pause");
	fclose(stdout);
	FreeConsole();
}


void ConsoleHlp::reopen_std(){
	// 原始fileno有可能是无效的,也可能是上次已关闭的
	_out = (_fileno(stdout) == 1) ? _dup(1) : -1;
	//_in = (_fileno(stdin) == 0) ? _dup(0) : -1;
	
	_wfreopen(L"CONOUT$", L"w+t", stdout);
	//_wfreopen(L"CONIN$", L"r+t", stdin);
	
	// 下为手动重定向，与系统方法结果一样(查前后文件号)
	// 无论什么方法，重定向stdin之后VC8有机率死掉
	if (0){
		HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
		int fdout = _open_osfhandle((intptr_t)hout, _O_TEXT);
		if (_out < 0){ // 无效stdout, 直接拷贝，用完关闭，无需还原
			FILE* fp = _wfdopen(fdout, L"w+t");
			*stdout = *fp;
		}
		else{
			_dup2(fdout, 1); _close(fdout);
		}
	}
	if (0) {	
		HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
		int fdin = _open_osfhandle((intptr_t)hin, _O_TEXT);
		if (_in < 0){
			FILE* fp = _wfdopen(fdin, L"r+t");
			*stdin = *fp;
		}
		else{
			_dup2(fdin, 0); _close(fdin);
		}
	}
	
	setvbuf(stdout, NULL, _IONBF, 0);
	_wsetlocale(LC_ALL, L"");
	
	// wprintf(L"bakup std=%d %d, reopened std=%d %d\n", _out, _in, _fileno(stdout), _fileno(stdin));
}

// 恢复重定向, 多种VC库同时注入测试，暂无异常
void ConsoleHlp::restory_std(){
	if (_out < 0){	// 原先stdout无效,此时stdout为新打开的（vc8必须关闭)
		fclose(stdout);
	}
	else {	// 原先stdout为标准输出流，如果使用fclose，则下次重定向时stdout文件号丢失
		_close(1); _dup2(_out, 1); _close(_out);
	}
	
	return;
	if (_in < 0){
		fclose(stdin);
	}
	else{
		_close(0); _dup2(_in, 0); _close(_in);
	}
}

// 附带一个简单钩子应用
SingleHooker::SingleHooker()
{
	_addr = 0; _val = 0; _orig = 0;
}

SingleHooker::~SingleHooker()
{
	Stop();
}

// 启动钩子
int __stdcall SingleHooker::Start()
{
	if (!_orig && _addr && _val){
		outlog(L"启动钩子!\n");
		return EditMemory(_addr, _val, &_orig);
	}
	return 1;	
}

// 停止钩子
int __stdcall SingleHooker::Stop()
{
	if (_orig && _addr){
		outlog(L"停止钩子!\n");
		EditMemory(_addr, _orig);
		_orig = 0;
	}
	return 1;
}

// 绑定虚函数
int __stdcall SingleHooker::SetVTable(void* object, int offset, void* func, void** orig_func)
{
	_addr = *(char**)object + offset;
	_val = func;
	*orig_func = *(void**)_addr;
	return 1;
}

// 绑定EIP， 暂支持ff15, e8, f8 三种Call
int __stdcall SingleHooker::SetEip(void* eip, void* func, void** orig_func)
{
	if (_orig) return 0;	// 如果hook了，保存orig，反之清空此值
	// 最起码eip得可读
	DWORD protect = PAGE_EXECUTE_READ, bak_protect = 0;
	if (!VirtualProtect(eip, sizeof(void*) * 2, protect, &bak_protect)){
		return 0;
	}

	if (*(WORD*)eip == 0x15ff){	// ff15 op => call dword ptr [op]
		_addr = (char*)eip + 2;			// 要修改的地址
		*orig_func = **(void***)_addr;	// 取一次为操作数(op)，再取一次为函数地址
		static void* tmp; tmp = func;	// 新地址也改为间接寻址, 对_val指针取值才是函数地址；
		_val = &tmp;
	}
	else if (*(BYTE*)eip == 0xe8){	// e8 op = call (op + next_eip)
		_addr = (char*)eip + 1;
		UINT_PTR next_eip = (UINT_PTR)_addr + sizeof(void*);
		*(UINT_PTR*)orig_func = *(UINT_PTR*)_addr + next_eip;	// 函数地址为: 操作数 + NextEIP
		*(UINT_PTR*)& _val = (UINT_PTR)func - next_eip;			// 新操作数为：函数地址 - NextEIP
	}
	else if (*(BYTE*)eip == 0xf8){	// f8 op = call op
		_addr = (char*)eip + 1;
		*orig_func = *(void**)_addr;	// 操作数即为函数地址
		_val = func;
	}
	return 1;
}

// 写内存
int __stdcall SingleHooker::EditMemory(void* addr, void* val, void** orig)
{
	DWORD protect = PAGE_EXECUTE_READWRITE, bak_protect = 0;
	if (VirtualProtect(addr, 4, protect, &bak_protect)){
		if (orig) *orig = *(void**)addr;
		*(void**)addr = val;
		return VirtualProtect(addr, 4, bak_protect, &protect);
	}
	return 0;
}

