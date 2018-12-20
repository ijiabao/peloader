/*
* @Author: iJiabao <ijiabao@qq.com>
* @Home: https://github.com/ijiabao
*/

#pragma once

#pragma warning(disable:4996)	//swprintf
#pragma warning(disable:4312)	//small to big

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>

namespace Log
{
	int __stdcall Init(const wchar_t* file = 0);
	int __stdcall Free();
	int __cdecl out(const wchar_t* format, ...);
	int __cdecl outA(const char* format, ...);
	
	struct Help{
		Help(const wchar_t* file = 0) {Init(file);}
		~Help() { Free();}
	};
}


#ifndef __LOG_H__
#define outlog Log::out
#define outlogA Log::outA
//#define outlog wprintf
//#define outlogA printf
#endif

// 模块附带数据
struct ModuleExtData{
	HWND hwnd;
	wchar_t loader_dir[1];
};

ModuleExtData* GetModuleExtData();

// 附带一个终端,调试输出用
class ConsoleHlp{
protected: 
	int _out, _in;
	HWND _hConsole;
public:
	ConsoleHlp();
	~ConsoleHlp();

	inline HWND GetHwnd() { return _hConsole; }
	void reopen_std();
	void restory_std();
};

// 附带一个简单钩子
class SingleHooker{
protected:
	void *_addr, *_val, *_orig;
public:
	SingleHooker();
	virtual ~SingleHooker();
	
	int __stdcall Start();
	int __stdcall Stop();
	
	int __stdcall SetVTable(void* object, int offset, void* func, void** orig_func);
	int __stdcall SetEip(void* eip, void* func, void** orig_func);
	static int __stdcall EditMemory(void* addr, void* val, void** orig = 0);
};