/*
* @Author: iJiabao <ijiabao@qq.com>
* @Home: https://github.com/ijiabao
*/

#include "pe_loader.h"
#include <shellapi.h>

#pragma warning (disable:4996)
#pragma warning (disable:4312)

PELoader::PELoader(){
	_module = 0;
	_extdata = 0;
	_extdata_size = 0;
}

PELoader::~PELoader(){
	Release();
}
// 释放内存
int __stdcall PELoader::Release(){
	if(_module){
		int result = VirtualFree(_module, 0, MEM_RELEASE);
		_module = NULL;
		outlog(result ? L"PE内存释放失败！\n" : L"PE内存释放成功！\n");
	}
	_extdata = 0; _extdata_size = 0;
	return 1;
}

// 简单验证PE头信息
int __stdcall PELoader::ValidNTHeader(const void* header){
	if (((IMAGE_DOS_HEADER*)header)->e_magic != IMAGE_DOS_SIGNATURE){
		outlog(L"无效的PE数据！\n");
		return 0;
	}
	IMAGE_NT_HEADERS* nth = NTHEADER(header);
	if (nth->Signature != IMAGE_NT_SIGNATURE){
		outlog(L"无效的PE数据！\n");
		return 0;
	}
	WORD magic = nth->OptionalHeader.Magic;
	if(IMAGE_NT_OPTIONAL_HDR32_MAGIC == magic && (sizeof(void*) != 4)){	//32位头
		outlog(L"目标PE为32位, 请运行本程序的32位版本\n");
		return 0;
	}
	if(IMAGE_NT_OPTIONAL_HDR64_MAGIC == magic && sizeof(void*) != 8){
		outlog(L"目标PE为64位, 请运行本程序的32位版本\n");
		return 0;
	}
	if(IMAGE_ROM_OPTIONAL_HDR_MAGIC == magic){
		outlog(L"非可执行文件\n");
		return 0;
	}
	return 1;
}



int __stdcall PELoader::CreateImage(const wchar_t* filename){
	FILE* fp = _wfopen(filename, L"rb");
	if (!fp) return 0;

	IMAGE_DOS_HEADER dosh;
	IMAGE_NT_HEADERS nth;

	fread(&dosh, sizeof(dosh), 1, fp);
	fseek(fp, dosh.e_lfanew, SEEK_SET);
	fread(&nth, sizeof(nth), 1, fp);
	
	SIZE_T image_size = nth.OptionalHeader.SizeOfImage;
	void* alloc_addr = (void*) nth.OptionalHeader.ImageBase;
	// 尝试以PE的参考基址来开辟空间,若成功则不需要重定位
	void* img = VirtualAlloc(alloc_addr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!img){
		img = VirtualAlloc(0, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	if (!img){
		fclose(fp);
		outlog(L"分配页面内存失败!\n");
		return 0;
	}
	outlog(L"参考基址为:%p\n", (void*)(UINT_PTR)nth.OptionalHeader.ImageBase);
	outlog(L"分配DLL映像基址为：%p, 大小为0x%x(%dkb)\n", img, image_size, image_size / 0x1000);


	// 拷入所有头(尽量不要头),防止暴力搜索
	fseek(fp, 0, SEEK_SET);
	fread(img, nth.OptionalHeader.SizeOfHeaders, 1, fp);
	//memcpy(img, rawdata, nth.OptionalHeader.SizeOfHeaders);
	// 复制RAW数据到各个节, NT头部结束后,紧接着就是第一个节数据
	IMAGE_NT_HEADERS* h = NTHEADER(img);
	IMAGE_SECTION_HEADER* seg = IMAGE_FIRST_SECTION(h);
	for (int i = 0; i< nth.FileHeader.NumberOfSections; i++){
		if (!seg->VirtualAddress || !seg->Misc.VirtualSize){
			continue; //空节？
		}
		void* dest = (char*)img + seg->VirtualAddress;
		//void* src = (char*)rawdata + seg->PointerToRawData;

		// sizeRawData, VirtualSize 参见微软MSDN http://msdn.microsoft.com/en-us/library/ms680341(v=vs.85).aspx
		DWORD size = seg->Misc.VirtualSize;
		if (size > seg->SizeOfRawData){	// 目标占用空间比源数据大
			size = seg->SizeOfRawData;	// 用零填充未初始化数据
			memset((char*)dest + size, 0, seg->Misc.VirtualSize - size);
		}
		//memmove(page, data, size);
		fseek(fp, seg->PointerToRawData, SEEK_SET);
		fread(dest, size, 1, fp);

		//节名称大于8个字符时，尾部的'\0'会被覆盖.
		char name[9]; name[8] = 0;
		memcpy(name, seg->Name, 8);
		outlogA("已复制：节名%s\t大小%d(bytes)\n", name, size);
		seg++;
	}
	_module = img;
	//UnloadRaw(rawdata);
	return 1;
}


// 处理导入函数表, 注意基址以this->_module为准,至NTHEADER(_module)->ImageBase是多少不必考虑
// 若需更完善,除导入表外,还要检查以下表:
// IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT [绑定导入表]
// IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT [延迟导入表]
// IMAGE_DIRECTORY_ENTRY_IAT 导入地址表, 下面的iat_thunk就是指向这里的某个项目

int __stdcall PELoader::FixupImports(){
	outlog(L"处理引入表...\n");
	
	PIMAGE_NT_HEADERS nth = NTHEADER(_module);
	//UINT_PTR image = nth->OptionalHeader.ImageBase;
	
	UINT_PTR image = (UINT_PTR) _module;
	
	IMAGE_DATA_DIRECTORY dir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if(!dir.Size){
		outlog(L"无导入表!\n"); return 0;
	}

	// 表游标
	IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*) (image + dir.VirtualAddress);
	
	// 遍历desc(数组)，每项desc记录了一个dll名称，以及对应dll的函数名称表(orig_thunk)，一个IAT地址表(iat_thunk)
	while (import_desc->Characteristics){	// 0 for terminating null import descriptor
		char* dllname = (char*)image + import_desc->Name;	//dll名
		//__outvar(import_desc->TimeDateStamp, "[DWORD]%d");	//时间戳
		//__outvar(import_desc->ForwarderChain, "[DWORD]%x");	
		IMAGE_THUNK_DATA* orig_thunk = (IMAGE_THUNK_DATA*)	//函数名表
			(image + import_desc->OriginalFirstThunk);
		IMAGE_THUNK_DATA* iat_thunk = (IMAGE_THUNK_DATA*)	//对应的IAT地址表
			(image + import_desc->FirstThunk);
		//

		//outlogA("%s\n", dllname);
		HMODULE import_dll = 0;
		if (!(import_dll = GetModuleHandleA(dllname))){
			if (!(import_dll = LoadLibraryA(dllname))){
				outlog(L"加载引入的Dll失败！\n");
				return 0;
			}
		}

		//依次从OriginaThunk得到函数名或序号,获取函数地址后写入对应的IAT地址
		while (orig_thunk->u1.Function){
			// 对于orig_thunk, 记录的是函数名称(或序号)
			char* func_name = 0;
			if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)){		// 序号引用, 最高位为1
				func_name = (char*) IMAGE_ORDINAL(orig_thunk->u1.Ordinal);	// 取低4位; 64位系统为低8位
			}
			else {	//函数名 (RVA)
				PIMAGE_IMPORT_BY_NAME iibn = (PIMAGE_IMPORT_BY_NAME)
					(image + (UINT_PTR)orig_thunk->u1.AddressOfData); // for vc6 must (UINT_PTR)
				func_name = (char*)(iibn->Name);
			}

			// 对于iat_thunk, 记录的是IAT项(的引用地址),可直接修改.下面写法兼容64位系统. iat_thunk == &iat_thunk->u1.Function
			*(FARPROC*)iat_thunk = GetProcAddress(import_dll, func_name);
			
			// 调试信息
			//outlogA("\tIAT [%08p]\tAddress [%08p]", iat_thunk, (void*)(UINT_PTR)iat_thunk->u1.Function);

			orig_thunk++;
			iat_thunk++;
		}
		import_desc++;
	}
	return 1;
}

// 根据实际基址与nth->ImageBase的偏移量，调整重定位表；目标基址默认为this->_module，调整后，可以在本地执行
int __stdcall PELoader::FixupRelocations(void* real_base){
	
	UINT_PTR image = (UINT_PTR)_module;
	PIMAGE_NT_HEADERS nth = NTHEADER(_module);
	if (!real_base) real_base = _module;
	//实际基址与参考基址之差
	UINT_PTR delta = (UINT_PTR)real_base - (UINT_PTR) nth->OptionalHeader.ImageBase;
	if(0 == delta){
		outlog(L"不需要重定位\n");
		return 1;
	}
	
	// 查重定位表。实际整个程序没几行，就一个遍历，一个处理。
	int index = IMAGE_DIRECTORY_ENTRY_BASERELOC;
	if (nth->OptionalHeader.DataDirectory[index].Size <= 0){	//没有重定位表?
		return 1;
	}
	outlog(L"处理重定位:\n");
	// 重定位API（未公开)， 处理IMAGE_BASE_RELOCATION记录，返回下一个记录
	PIMAGE_BASE_RELOCATION(APIENTRY* LdrProcessRelocationBlock)(PVOID Page, DWORD Count, PUSHORT TypeOffset, UINT_PTR Delta) = 0;
	*(FARPROC*)& LdrProcessRelocationBlock = GetProcAddress(GetModuleHandle(L"NTDLL"), "LdrProcessRelocationBlock");
	if(!LdrProcessRelocationBlock){	//备用API
		LdrProcessRelocationBlock = MyProcessRelocationBlock;
	}
	
	// 得到第一个重定位记录(块)
	PIMAGE_BASE_RELOCATION reloc = (IMAGE_BASE_RELOCATION*)
		(image + nth->OptionalHeader.DataDirectory[index].VirtualAddress);
	// 遍历每个块，块首是一个reloc结构（暂称‘表’），表后紧接着是重定位数据(数组）。参见此块的struct定义
	while (reloc->VirtualAddress){
		// 重定位所在的目标页
		UINT_PTR dest_page = image + reloc->VirtualAddress;
		// 下列等同于 (UINT_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION);
		USHORT *items = (USHORT*)(reloc + 1);
		// 数据个数 = 块大小-表大小 / 单个数据大小
		DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		// 调试信息:
		//char name[9]; memset(name, 0, 9);
		//GetSectionName((void*)dest_page, name);
		//outlogA("页址:%p\t节名:%s\t项数:%d\t块大小:%d\n", dest_page, name, count, reloc->SizeOfBlock);
		// 处理重定位记录,返回下一个reloc指针
		reloc = LdrProcessRelocationBlock((void*)dest_page, count, items, delta);
		if(!reloc) return 0;
	}
	//修正ImageBase
	//*(UINT_PTR*)&nth->OptionalHeader.ImageBase = (UINT_PTR)dest;
	return 1;
}

// 备用重定位处理, 来自win2k源码，已通过64位测试
PIMAGE_BASE_RELOCATION APIENTRY PELoader::MyProcessRelocationBlock(PVOID Page, DWORD Count, PUSHORT TypeOffset, UINT_PTR Delta){
	UINT_PTR dest_page = (UINT_PTR)Page;
	PUSHORT items = TypeOffset;
	UINT_PTR delta = Delta;
	// 验证, 块地址 = TypeOffset - sizeof(IMAGE_BASE_RELOCATION);	//参见IMAGE_BASE_RELOCATION定义
	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((UINT_PTR)TypeOffset - sizeof(IMAGE_BASE_RELOCATION));
	DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
	if(Count != count) return 0;
	
	// 下面是从Win2K源码里找到的，是上述API的实现过程，供研究，增加了64位处理，通过了测试
	for (DWORD i = 0; i<count; i++){
		DWORD item = items[i];
		int offset = item & 0xFFF;	//低12位, 偏移值
		int type = item >> 12;		//高4位, 重定位类型（修改方式）

		UINT_PTR dest = dest_page + offset; // （指向）要修改的“地址”
		switch (type){
		case IMAGE_REL_BASED_ABSOLUTE:
			break;
		case IMAGE_REL_BASED_HIGH:
			*(PUSHORT)dest += HIWORD(delta);
			break;
		case IMAGE_REL_BASED_LOW:
			*(PUSHORT)dest += LOWORD(delta);
			break;
		case IMAGE_REL_BASED_HIGHLOW:
			// 假如目标内容是 A1 ( 0c d4 02 10)  汇编代码是： mov eax , [1002d40c]
			// 则dest指向括号，我们要修改0x1002d40c这个32位“地址”
			*(PUINT_PTR)dest += delta;
			break;
		case IMAGE_REL_BASED_DIR64:
			*(PUINT_PTR)dest += delta;
			break;
		case IMAGE_REL_BASED_HIGHADJ:
		case IMAGE_REL_BASED_MIPS_JMPADDR:
		case IMAGE_REL_BASED_MIPS_JMPADDR16:	//IMAGE_REL_BASED_IA64_IMM64
		default:
			//wprintf(L"未知/不支持的重定位类型 %hu.\n", type);
			return 0;
		}

	}
	//返回下一条记录
	return (PIMAGE_BASE_RELOCATION)((UINT_PTR)reloc + reloc->SizeOfBlock);
	
}


// 获取导出函数, 基址以this->_module为准
FARPROC PELoader::GetProcAddr(char* name){
	PIMAGE_NT_HEADERS nth = NTHEADER(_module);
	//UINT_PTR img = _nth->OptionalHeader.ImageBase;
	UINT_PTR img = (UINT_PTR)_module;
	int index = IMAGE_DIRECTORY_ENTRY_EXPORT;
	if (!nth->OptionalHeader.DataDirectory[index].Size){
		return NULL;
	}

	IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)
		(img + nth->OptionalHeader.DataDirectory[index].VirtualAddress);

	// 注:三个数组和基数的关系:Functions[], Names[], NameOrdinals[], Base
	// 按函数序号取址: 函数地址 = Functions[序号 - 基数];  (此序号应称作'编号'更为贴切,编号=序号+基数)
	// 按函数名取地址: 若Names[N]=函数名, 则序号ordinals = NameOrdinals[N] (见注), 则函数地址 = Functions[ordinals]
	// 可见 NameOrdinals[]数组取得的‘序号’值,实际就是下标,最小值为0,不是真正意义上的函数导出序号
	// 		题外话:之前见网上很多教程有Names[N] 得 序号= ordinals[N]+基数-1, 再得Function[序号], 其中的+基数-1是无厘头的,没任何意义;
	// 通常默认基数为1, 则公式变为:序号=ordinals[N], 已测试在生成Dll时指定基数不为1, 再用此公式,则程序必然出错, 加基数再减1,不知意义在哪;
	// 看来网上的东西也不一定是正确的,一定要自已验证才是真理

	DWORD*	names = (DWORD*)(img + ied->AddressOfNames);
	WORD*	ordinals = (WORD*)(img + ied->AddressOfNameOrdinals);
	DWORD*	funcs = (DWORD*)(img + ied->AddressOfFunctions);

	int ordinal = -1;
	if (HIWORD(name) == 0){ //序号引用
		ordinal = LOWORD(name) - ied->Base;
		//__outlogA("序号引用%d\n", ordinal);
	}
	else { // 搜函数名，得到序号
		for (DWORD i = 0; i < ied->NumberOfNames; i++){
			char* curr_name = (char*)(img + names[i]);
			if (strcmp(name, curr_name) == 0){
				//__outlogA("找到函数名=%s", curr_name);
				ordinal = ordinals[i];
				break;
			}
		}
	}

	if (ordinal < 0 || (DWORD)ordinal >= ied->NumberOfFunctions){
		return NULL;
	}

	return (FARPROC)(img + funcs[ordinal]);
}

// 调用Dll入口点
int __stdcall PELoader::RunDllMainCRTStartup(DWORD ul_reason_for_call, LPVOID lpReserved){
	DllMainCRTStartupProc DllMain = 
		(DllMainCRTStartupProc)RVA(_module, NTHEADER(_module)->OptionalHeader.AddressOfEntryPoint);
	if(DllMain){
		return DllMain((HMODULE)_module, ul_reason_for_call, lpReserved);
	}
	return 0;
}


// 抹去头信息
int __stdcall PELoader::HackHeader(){
	if(!_module) return 0;
	UINT_PTR img = (UINT_PTR) _module;
	PIMAGE_NT_HEADERS nth = NTHEADER(_module);
	
	// 去除OptionalHeader标志
	nth->OptionalHeader.Magic = 0;
	// 去除Dll名字
	IMAGE_DATA_DIRECTORY idd = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if(idd.Size){
		IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)(img + idd.VirtualAddress);
		*(char*)(img + ied->Name) = 0;	//将字符串的第一字节改为0
	}
	// 其它NtHeader等信息直接置0
	UINT_PTR fillsize = (UINT_PTR) &nth->OptionalHeader - img;
	ZeroMemory((void*)img, fillsize);
	return 0;
}


// 计算对齐后的长度
SIZE_T CaleAlignmentSize(int origin, int alignment){
	return (origin + alignment - 1) / alignment * alignment;
}

// 创建远程PE映像, 并得到远程线的程起始函数
// 通常在远程使用自删除程序来释放远程PE内存, 见底部示例
// 附加数据放在image后面
void* __stdcall PELoader::Inject(HANDLE hProcess, char* StartFunc, void** ThreadMain){
	if(!(_module && hProcess)) return 0;
	UINT_PTR ThreadStart = (UINT_PTR) GetProcAddr(StartFunc);
	if(!ThreadStart){
		outlog(L"PE内未定义线程起始函数!\n");
		return 0;
	}

	SIZE_T size_data = CaleAlignmentSize(_extdata_size, 4096);
	
	//SIZE_T size_data = _aligned_msize()
	// 附加数据
	//SIZE_T size_data = 4096;
	//char params[4096];
	//GetCurrentDirectory(MAX_PATH, (wchar_t*)params);
	
	IMAGE_NT_HEADERS* nth = NTHEADER(_module);
	UINT_PTR size_image = nth->OptionalHeader.SizeOfImage;

	void* remote = VirtualAllocEx(hProcess, 0, size_image + size_data, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!remote){ return 0; }
	FixupImports();
	FixupRelocations(remote);
	
	// 换算起始线程函数的远程地址
	*(UINT_PTR*)ThreadMain = (UINT_PTR)remote + (ThreadStart - (UINT_PTR)_module);
	// 写入远程
	SIZE_T written = 0;
	WriteProcessMemory(hProcess, remote, (void*)_module, size_image, &written);
	if(written != size_image){
		return 0;
	}

	if (size_data){
		// 数据附在image后面
		written = 0;
		WriteProcessMemory(hProcess, ((char*)remote + size_image), _extdata, size_data, &written);
		if (written != size_data){
			return 0;
		}
	}
	

	return remote;
}






int __stdcall PELoader::EnableDebugPrivileges(){
	HANDLE token = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
		outlog(L"打开进程特权令牌失败! 错误码:%d\n", GetLastError());
		return 0;
	}
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(token, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		outlog(L"提升令牌特权失败! 错误码:%d\n", GetLastError());
		return FALSE;
	}
	outlog(L"调整权限成功!\n");
	if (ERROR_NOT_ALL_ASSIGNED == GetLastError()) {
		outlog(L"提示:并非所有被引用的特权或组都分配给呼叫方。\n");
		SetLastError(0);
	}
	CloseHandle(token);
	return 1;
}

// 判断是否以管理员身份运行
int __stdcall PELoader::IsElevatedToken(){
	OSVERSIONINFOEX ovi;
	memset(&ovi, 0, sizeof(OSVERSIONINFOEX));
	ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((LPOSVERSIONINFO)&ovi)){
		if (ovi.dwMajorVersion < 6){
			// 低于Vista
			return 1;
		}
	}
	WORD version = LOWORD(GetVersion());
	version = MAKEWORD(HIBYTE(version), LOBYTE(version));
	if (version < 0x0600){ // 低于Vista，不需要权限认证
		return 1;
	}

	// VC6需定义
	struct /*TOKEN_ELEVATION*/ {
		DWORD TokenIsElevated;
	} te = { 0 };
	enum { TokenElevation = 20 };

	HANDLE token = 0;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		DWORD len;
		GetTokenInformation(token, (TOKEN_INFORMATION_CLASS)TokenElevation, &te, sizeof(te), &len);
	}
	return te.TokenIsElevated;
}

// 获取模块文件的目录,默认为当前可执行文件
int __stdcall PELoader::GetCurrentModuleDir(wchar_t* dir, int maxlen){
	HMODULE	module = GetModuleHandle(0);
	//ZeroMemory(dir, sizeof(wchar_t)*maxlen);
	if(!GetModuleFileName(module, dir, maxlen)){
		return 0;
	}
	wchar_t* i = wcsrchr(dir, '\\');
	if(i) *i=0;
	return 1;
}

int __stdcall PELoader::SetCurrentExecDir(){
	wchar_t buffer[MAX_PATH];
	ZeroMemory(buffer, sizeof(buffer));
	if(!GetCurrentModuleDir(buffer, MAX_PATH)){
		return 0;
	}
	return SetCurrentDirectory(buffer);
}

// 新实例运行之后再关闭本程序
int __stdcall PELoader::RunasAdmin(const wchar_t* params){
	wchar_t file[MAX_PATH];
	ZeroMemory(file, sizeof(wchar_t) * MAX_PATH);
	if(!GetModuleFileName(NULL, file, MAX_PATH)){
		return 0;
	}
	
	SHELLEXECUTEINFO sei;
	ZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));
	sei.cbSize = sizeof(SHELLEXECUTEINFO);
	sei.lpVerb = L"runas";
	sei.lpFile = file;
	sei.lpParameters = params;
	sei.nShow = SW_SHOWNORMAL;
	
	if(ShellExecuteEx(&sei)){
		return 1;
	}
	
	DWORD err = GetLastError();
	if(ERROR_CANCELLED == err){
		outlog(L"取消执行\n");
	}
	else if(ERROR_FILE_NOT_FOUND == err){
		outlog(L"文件未找到\n");
	}
	return 0;
}


int __stdcall PELoader::TestInject(HWND hwnd, wchar_t* dllfile, int wait){
	if(!hwnd){
		outlog(L"窗口不存在!\n");
		return 0;
	}
	// 打开进程
	DWORD pid = 0;
	if(!GetWindowThreadProcessId(hwnd, &pid)){
		return 0;
	}
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	
	if(!process){
		if(ERROR_ACCESS_DENIED == GetLastError()){
			outlog(L"无权访问目标进程!\n");
			if(!IsElevatedToken()) return RunasAdmin(0);
			return -1;
		}
		outlog(L"打开进程失败！\n");
		return 0;
	}

	SetCurrentExecDir();

	char extdata[4096];
	*(HWND*)(extdata) = hwnd;
	GetCurrentDirectory(4094, (wchar_t*)(extdata + 4));

	PELoader loader;
	if(!loader.CreateImage(dllfile)){
		CloseHandle(process);
		outlog(L"加载dll文件失败!\n");
		return 0;
	}
	loader.SetExtData(extdata, 4096);

	void* ThreadMain = 0;
	void* remote = loader.Inject(process, "RemoteCRTStartup", &ThreadMain);
	if(!remote){
		outlog(L"创建远程PE失败!\n");
		CloseHandle(process);
		return 0;
	}

	HANDLE hThread = CreateRemoteThread(process, 0, 0, (LPTHREAD_START_ROUTINE)ThreadMain, (void*)remote, 0, 0);
	if(!hThread){
		outlog(L"启动远程线程失败!\n");
		CloseHandle(process);
		return 0;
	}

	outlog(L"远程线程已启动!\n");

	if(wait){
		WaitForSingleObject(hThread, -1);
		DWORD code = 0;
		int temp = GetExitCodeThread(hThread, &code);
		outlog(L"线程结束,返回值:%d\n", code);
		CloseHandle(hThread);
		if(loader.UnInject(process, remote)){
			outlog(L"远程内存空间已释放！\n");
		}
	}
	
	CloseHandle(process);
	return 1;
}