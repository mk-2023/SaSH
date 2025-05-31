/*
				GNU GENERAL PUBLIC LICENSE
				   Version 2, June 1991
COPYRIGHT (C) Bestkakkoii 2024 All Rights Reserved.
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

*/

#include "stdafx.h"
#include "mainform.h"
#include "util.h"
#include <gamedevice.h>
#include "net/rpc.h"
#include <QCommandLineParser>

#pragma comment(lib, "ws2_32.lib")
#include <DbgHelp.h>
#include <regex>
#pragma comment(lib, "dbghelp.lib")

#pragma region sp
namespace process_spoofer
{
	////////////////////////////////////////////////////////////////////////////
	// 動態載入 API 輔助函數：傳入 DLL 名稱及函數名稱，回傳對應函數指標
	static inline FARPROC LoadAPI(const char* moduleName, const char* functionName)
	{
		HMODULE hModule = GetModuleHandleA(moduleName);
		if (!hModule) {
			hModule = LoadLibraryA(moduleName);
		}
		if (!hModule) {
			return nullptr;
		}
		return GetProcAddress(hModule, functionName);
	}

	////////////////////////////////////////////////////////////////////////////
	// 全域函數指標宣告（均以動態載入方式取得）

	// ntdll.dll 內 API
	typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
		);
	pNtQuerySystemInformation g_NtQuerySystemInformation = nullptr;

	// RtlGetVersion 用來取得 OS 版本資訊 (來自 ntdll.dll)
	typedef LONG(WINAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW);
	pRtlGetVersion g_RtlGetVersion = nullptr;

	// NtReadVirtualMemory 與 NtWriteVirtualMemory (取代 Read/WriteProcessMemory)
	typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToRead,
		PSIZE_T NumberOfBytesRead
		);
	pNtReadVirtualMemory g_NtReadVirtualMemory = nullptr;

	typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToWrite,
		PSIZE_T NumberOfBytesWritten
		);
	pNtWriteVirtualMemory g_NtWriteVirtualMemory = nullptr;

	// advapi32.dll 內 API: OpenProcessToken, LookupPrivilegeValueW, AdjustTokenPrivileges
	typedef BOOL(WINAPI* pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
	pOpenProcessToken g_OpenProcessToken = nullptr;

	typedef BOOL(WINAPI* pLookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
	pLookupPrivilegeValueW g_LookupPrivilegeValueW = nullptr;

	typedef BOOL(WINAPI* pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
	pAdjustTokenPrivileges g_AdjustTokenPrivileges = nullptr;

	// kernel32.dll 內 API: OpenProcess, GetCurrentProcess, GetCurrentProcessId, CloseHandle
	typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
	pOpenProcess g_OpenProcess = nullptr;

	typedef HANDLE(WINAPI* pGetCurrentProcess)(VOID);
	pGetCurrentProcess g_GetCurrentProcess = nullptr;

	typedef DWORD(WINAPI* pGetCurrentProcessId)(VOID);
	pGetCurrentProcessId g_GetCurrentProcessId = nullptr;

	typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
	pCloseHandle g_CloseHandle = nullptr;

	////////////////////////////////////////////////////////////////////////////
	// 系統句柄資訊結構（根據非官方資料整理）
	typedef struct _SYSTEM_HANDLE
	{
		ULONG   ProcessId;        // 擁有此句柄的進程 PID
		BYTE    ObjectTypeNumber;
		BYTE    Flags;
		USHORT  Handle;           // 句柄值
		PVOID   Object;           // 內核中該對象的指標 (例如 EPROCESS)
		ACCESS_MASK GrantedAccess;
	} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		ULONG HandleCount;
		SYSTEM_HANDLE Handles[1]; // 可變長度陣列
	} *PSYSTEM_HANDLE_INFORMATION;

	////////////////////////////////////////////////////////////////////////////
	// 初始化所有所需 API（動態載入各 DLL 中的函數）
	static bool initializeAPIs()
	{
		// 從 ntdll.dll 載入 NtQuerySystemInformation、RtlGetVersion、NtReadVirtualMemory 與 NtWriteVirtualMemory
		g_NtQuerySystemInformation = (pNtQuerySystemInformation)LoadAPI("ntdll.dll", "NtQuerySystemInformation");
		g_RtlGetVersion = (pRtlGetVersion)LoadAPI("ntdll.dll", "RtlGetVersion");
		g_NtReadVirtualMemory = (pNtReadVirtualMemory)LoadAPI("ntdll.dll", "NtReadVirtualMemory");
		g_NtWriteVirtualMemory = (pNtWriteVirtualMemory)LoadAPI("ntdll.dll", "NtWriteVirtualMemory");
		if (!g_NtQuerySystemInformation || !g_RtlGetVersion ||
			!g_NtReadVirtualMemory || !g_NtWriteVirtualMemory)
		{
			return false;
		}

		// 從 advapi32.dll 載入 OpenProcessToken、LookupPrivilegeValueW、AdjustTokenPrivileges
		g_OpenProcessToken = (pOpenProcessToken)LoadAPI("advapi32.dll", "OpenProcessToken");
		g_LookupPrivilegeValueW = (pLookupPrivilegeValueW)LoadAPI("advapi32.dll", "LookupPrivilegeValueW");
		g_AdjustTokenPrivileges = (pAdjustTokenPrivileges)LoadAPI("advapi32.dll", "AdjustTokenPrivileges");
		if (!g_OpenProcessToken || !g_LookupPrivilegeValueW || !g_AdjustTokenPrivileges)
		{
			return false;
		}

		// 從 kernel32.dll 載入 OpenProcess、GetCurrentProcess、GetCurrentProcessId、CloseHandle
		g_OpenProcess = (pOpenProcess)LoadAPI("kernel32.dll", "OpenProcess");
		g_GetCurrentProcess = (pGetCurrentProcess)LoadAPI("kernel32.dll", "GetCurrentProcess");
		g_GetCurrentProcessId = (pGetCurrentProcessId)LoadAPI("kernel32.dll", "GetCurrentProcessId");
		g_CloseHandle = (pCloseHandle)LoadAPI("kernel32.dll", "CloseHandle");
		if (!g_OpenProcess || !g_GetCurrentProcess || !g_GetCurrentProcessId || !g_CloseHandle)
		{
			return false;
		}
		return true;
	}

	////////////////////////////////////////////////////////////////////////////
	// 取得 OS 版本資訊，利用 RtlGetVersion（此 API 為非官方，但能正確取得版本資訊）
	static bool getOSVersion(OSVERSIONINFOEXW& osvi)
	{
		ZeroMemory(&osvi, sizeof(osvi));
		osvi.dwOSVersionInfoSize = sizeof(osvi);
		LONG status = g_RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
		return (status == 0);
	}

	////////////////////////////////////////////////////////////////////////////
	// 根據 OS 版本判斷並回傳 UniqueProcessId 欄位偏移量
	// 分為三組：Windows 7/8（假設偏移 0x2e8）、Windows 10（假設偏移 0x2e8）、Windows 11（假設偏移 0x448）
	static SIZE_T getUniqueProcessIdOffset()
	{
		OSVERSIONINFOEXW osvi = {};
		if (!getOSVersion(osvi))
		{
			return 0x2e8;  // 預設
		}

		// Windows 7/8：Major 6，Minor 1 ~ 3
		if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 1 && osvi.dwMinorVersion <= 3)
		{
			return 0x2e8;
		}
		// Windows 10：Major 10 且 Build < 22000
		else if (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber < 22000)
		{
			return 0x2e8;
		}
		// Windows 11：Major 10 且 Build >= 22000 (Windows 11 目前主版本仍為 10，但 Build 號較高)
		else if (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 22000)
		{
			return 0x448;
		}
		else
		{
			return 0x2e8;
		}
	}

	////////////////////////////////////////////////////////////////////////////
	// 提升權限：啟用 SeDebugPrivilege
	// 利用 OpenProcessToken、LookupPrivilegeValueW 與 AdjustTokenPrivileges 調整當前進程權杖
	static bool enableDebugPrivilege()
	{
		HANDLE hToken = nullptr;
		if (!g_OpenProcessToken(g_GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			return false;
		}
		LUID luid;
		if (!g_LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
			g_CloseHandle(hToken);
			return false;
		}
		TOKEN_PRIVILEGES tp = {};
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!g_AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
		{
			g_CloseHandle(hToken);
			return false;
		}
		g_CloseHandle(hToken);
		return (GetLastError() == ERROR_SUCCESS);
	}

	////////////////////////////////////////////////////////////////////////////
	// 修改目標進程的 PID (偽裝)
	// 流程：
	// 1. 提升權限，並以 PROCESS_ALL_ACCESS 開啟目標進程。
	// 2. 利用 NtQuerySystemInformation (SystemHandleInformation) 取得系統句柄列表，
	//    從中找出目標進程句柄對應的內核 EPROCESS 指標。
	// 3. 根據 OS 版本取得 UniqueProcessId 欄位偏移量，
	//    再利用 NtWriteVirtualMemory 嘗試寫入新的 PID 值（純用戶態下預期會失敗）。
	static bool spoofProcessId(DWORD targetPid, ULONG_PTR newPid)
	{
		if (!enableDebugPrivilege())
		{
			return false;
		}

		// 以 PROCESS_ALL_ACCESS 權限開啟目標進程
		HANDLE hTargetProc = g_OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
		if (!hTargetProc)
		{
			return false;
		}

		// 查詢系統句柄資訊
		ULONG handleInfoSize = 0x10000;  // 初始緩衝區大小
		std::vector<BYTE> handleBuffer;
		NTSTATUS status = 0;
		ULONG returnLength = 0;
		do
		{
			handleBuffer.resize(handleInfoSize);
			status = g_NtQuerySystemInformation(16, handleBuffer.data(), handleInfoSize, &returnLength);
			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				handleInfoSize *= 2;
			}
			else if (!NT_SUCCESS(status))
			{
				g_CloseHandle(hTargetProc);
				return false;
			}
		} while (status == STATUS_INFO_LENGTH_MISMATCH);

		// 從取得的句柄資訊中尋找目標進程的 EPROCESS 指標
		PSYSTEM_HANDLE_INFORMATION handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleBuffer.data());
		PVOID targetEprocess = nullptr;
		DWORD currentProcId = g_GetCurrentProcessId();
		// 取目標進程句柄的低 16 位 (系統句柄表中句柄值僅有 16 位)
		USHORT targetHandleValue = static_cast<USHORT>(reinterpret_cast<ULONG_PTR>(hTargetProc) & 0xFFFF);
		for (ULONG i = 0; i < handleInfo->HandleCount; ++i)
		{
			SYSTEM_HANDLE& h = handleInfo->Handles[i];
			if (h.ProcessId == currentProcId && h.Handle == targetHandleValue)
			{
				targetEprocess = h.Object;
				break;
			}
		}
		g_CloseHandle(hTargetProc); // 已取得 EPROCESS 指標，關閉句柄

		if (!targetEprocess)
		{
			return false;
		}

		// 根據 OS 版本取得 UniqueProcessId 欄位偏移量
		SIZE_T uniquePidOffset = getUniqueProcessIdOffset();
		PBYTE pidFieldAddress = reinterpret_cast<PBYTE>(targetEprocess) + uniquePidOffset;

		// 使用 NtReadVirtualMemory 嘗試讀取目前 PID (通常因內核保護而失敗)
		ULONG_PTR originalPidValue = 0;
		SIZE_T bytesRead = 0;
		NTSTATUS ntStatus = g_NtReadVirtualMemory(g_GetCurrentProcess(), pidFieldAddress,
			&originalPidValue, sizeof(originalPidValue), &bytesRead);
		if (NT_SUCCESS(ntStatus))
		{
		}
		else
		{
		}

		// 使用 NtWriteVirtualMemory 嘗試將新的 PID 寫入 UniqueProcessId 欄位
		SIZE_T bytesWritten = 0;
		ntStatus = g_NtWriteVirtualMemory(g_GetCurrentProcess(), pidFieldAddress,
			&newPid, sizeof(newPid), &bytesWritten);
		if (!NT_SUCCESS(ntStatus))
		{
			return false;
		}

		return true;
	}

} // End of namespace ProcessSpoofer
#pragma endregion

//堆棧追蹤
static void printStackTrace()
{
	util::TextStream out(stderr);
	void* stack[100];
	unsigned short frames;
	SYMBOL_INFO* symbol;
	HANDLE process;
	process = GetCurrentProcess();
	SymInitialize(process, NULL, TRUE);
	frames = CaptureStackBackTrace(0, 100, stack, NULL);
	symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
	if (symbol)
	{
		symbol->MaxNameLen = 255;
		symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		for (long long i = 0; i < frames; ++i)
		{
			SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);
			out << i << ": " << QString(symbol->Name) << " - " << symbol->Address << Qt::endl;
		}

		free(symbol);
	}
}

#if 0
static void qtMessageHandler(QtMsgType type, const QMessageLogContext& context, const QString& msg)
{
	if (type != QtCriticalMsg && type != QtFatalMsg)
	{
		return;
	}

	try
	{
		throw QException();
	}
	catch (const QException& e)
	{
		if (QString(e.what()).contains("Unknown exception"))
		{
			return;
		}

		for (long long i = 0; i < SASH_MAX_THREAD; ++i)
		{
			GameDevice* pinstance = nullptr;
			if (GameDevice::get(i, &pinstance) && pinstance != nullptr)
				pinstance->log.close();
		}

		util::TextStream out(stderr);
		out << QString("Qt exception caught: ") << QString(e.what()) << Qt::endl;
		out << QString("Context: ") << context.file << ":" << context.line << " - " << context.function << Qt::endl;
		out << QString("Message: ") << msg << QString(e.what()) << Qt::endl;
		printStackTrace();
		system("pause");

	}
}
#endif

#if defined _M_X64 || defined _M_IX86
static LPTOP_LEVEL_EXCEPTION_FILTER WINAPI
dummySetUnhandledExceptionFilter(
	LPTOP_LEVEL_EXCEPTION_FILTER)
{
	return NULL;
}
#else
#error "This code works only for x86 and x64!"
#endif

static BOOL preventSetUnhandledExceptionFilter()
{
	HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");
	if (hKernel32 == nullptr)
		return FALSE;

	void* pOrgEntry = GetProcAddress(hKernel32, "SetUnhandledExceptionFilter");
	if (pOrgEntry == nullptr)
		return FALSE;

	DWORD dwOldProtect = 0;
	SIZE_T jmpSize = 5;
#ifdef _M_X64
	jmpSize = 13;
#endif
	BOOL bProt = VirtualProtect(pOrgEntry, jmpSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	BYTE newJump[20];
	memset(newJump, 0, sizeof(newJump));
	void* pNewFunc = &dummySetUnhandledExceptionFilter;
#ifdef _M_IX86
	DWORD dwOrgEntryAddr = (DWORD)pOrgEntry;
	dwOrgEntryAddr += jmpSize; // add 5 for 5 op-codes for jmp rel32
	DWORD dwNewEntryAddr = (DWORD)pNewFunc;
	DWORD dwRelativeAddr = dwNewEntryAddr - dwOrgEntryAddr;
	// JMP rel32: Jump near, relative, displacement relative to next instruction.
	newJump[0] = 0xE9;  // JMP rel32
	memcpy(&newJump[1], &dwRelativeAddr, sizeof(pNewFunc));
#elif _M_X64
	// We must use R10 or R11, because these are "scratch" registers 
	// which need not to be preserved accross function calls
	// For more info see: Register Usage for x64 64-Bit
	// http://msdn.microsoft.com/en-us/library/ms794547.aspx
	// Thanks to Matthew Smith!!!
	newJump[0] = 0x49;  // MOV R11, ...
	newJump[1] = 0xBB;  // ...
	memcpy(&newJump[2], &pNewFunc, sizeof(pNewFunc));
	//pCur += sizeof (ULONG_PTR);
	newJump[10] = 0x41;  // JMP R11, ...
	newJump[11] = 0xFF;  // ...
	newJump[12] = 0xE3;  // ...
#endif
	SIZE_T bytesWritten;
	BOOL bRet = WriteProcessMemory(GetCurrentProcess(),
		pOrgEntry, newJump, jmpSize, &bytesWritten);

	if (bProt != FALSE)
	{
		DWORD dwBuf;
		VirtualProtect(pOrgEntry, jmpSize, dwOldProtect, &dwBuf);
	}
	return bRet;
}

static LONG CALLBACK MinidumpCallback(PEXCEPTION_POINTERS pException)
{
	do
	{
		if (!pException)
			break;

		//忽略可繼續執行的
		if (pException->ExceptionRecord->ExceptionFlags != EXCEPTION_NONCONTINUABLE)
		{
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		auto PathFileExists = [](const wchar_t* name)->BOOL
			{
				DWORD dwAttrib = GetFileAttributes(name);
				return (dwAttrib != INVALID_FILE_ATTRIBUTES && !util::checkAND(dwAttrib, FILE_ATTRIBUTE_DIRECTORY));
			};

		// Check if dump directory exists
		if (!PathFileExists(L".\\lib\\dump"))
		{
			CreateDirectory(L".\\lib\\dump", NULL);
		}

		wchar_t pszFileName[MAX_PATH] = {};
		SYSTEMTIME stLocalTime = {};
		GetLocalTime(&stLocalTime);
		swprintf_s(pszFileName, L"lib\\dump\\%04d%02d%02d_%02d%02d%02d.dmp",
			stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay,
			stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond);

		ScopedHandle hDumpFile(CreateFile(pszFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));
		if (hDumpFile == INVALID_HANDLE_VALUE)
			break;

		MINIDUMP_EXCEPTION_INFORMATION dumpInfo = {};
		dumpInfo.ExceptionPointers = pException;
		dumpInfo.ThreadId = GetCurrentThreadId();
		dumpInfo.ClientPointers = TRUE;

		MiniDumpWriteDump(
			GetCurrentProcess(),
			GetCurrentProcessId(),
			hDumpFile,
			(MINIDUMP_TYPE)(
				MiniDumpNormal
				| MiniDumpWithFullMemory
				| MiniDumpWithHandleData
				| MiniDumpWithThreadInfo
				| MiniDumpWithUnloadedModules
				| MiniDumpWithProcessThreadData
				),
			&dumpInfo,
			NULL,
			NULL
		);

		if (pException->ExceptionRecord->ExceptionFlags == EXCEPTION_NONCONTINUABLE)
		{

			QString msg = QString(
				"A fatal error occured, \r\n"
				"it's a noncontinuable exception, \r\n"
				"sorry but we have to terminate this program.\r\n"
				"please send minidump to developer.\r\n"
				"Basic Infomations:\r\n\r\n"
				"ExceptionAddress:0x%1\r\n"
				"ExceptionFlags:%2\r\n"
				"ExceptionCode:0x%3\r\n"
				"NumberParameters:%4")
				.arg(util::toQString(reinterpret_cast<unsigned long long>(pException->ExceptionRecord->ExceptionAddress), 16))
				.arg(pException->ExceptionRecord->ExceptionFlags == EXCEPTION_NONCONTINUABLE ? "NON CONTINUEABLE" : "CONTINUEABLE")
				.arg(util::toQString(static_cast<unsigned long long>(pException->ExceptionRecord->ExceptionCode), 16))
				.arg(pException->ExceptionRecord->NumberParameters);

			//Open dump folder
			MessageBoxW(nullptr, msg.toStdWString().c_str(), L"Fatal Error", MB_OK | MB_ICONERROR);
			ShellExecuteW(nullptr, L"open", L"dump", nullptr, nullptr, SW_SHOWNORMAL);

			for (long long i = 0; i < SASH_MAX_THREAD; ++i)
			{
				GameDevice* pinstance = nullptr;
				if (GameDevice::get(i, &pinstance) && pinstance != nullptr)
					pinstance->log.close();
			}

			throw EXCEPTION_EXECUTE_HANDLER;

			return EXCEPTION_CONTINUE_SEARCH;
		}
		else
		{
			QString msg = QString(
				"A warning error occured, it's a continuable exception \r\npress \'continue\' to skip this exception\r\n\r\n"
				"Basic Infomations:\r\n\r\n"
				"ExceptionAddress:0x%1\r\n"
				"ExceptionFlags:%2\r\n"
				"ExceptionCode:0x%3\r\n"
				"NumberParameters:%4")
				.arg(util::toQString(reinterpret_cast<unsigned long long>(pException->ExceptionRecord->ExceptionAddress), 16))
				.arg(pException->ExceptionRecord->ExceptionFlags == EXCEPTION_NONCONTINUABLE ? "NON CONTINUEABLE" : "CONTINUEABLE")
				.arg(util::toQString(static_cast<unsigned long long>(pException->ExceptionRecord->ExceptionCode), 16))
				.arg(pException->ExceptionRecord->NumberParameters);
			//QMessageBox::warning(nullptr, "Warning", msg);
			//ShellExecuteW(NULL, L"open", L"dump", NULL, NULL, SW_SHOWNORMAL);
		}
	} while (false);

	return EXCEPTION_CONTINUE_SEARCH;
}

static void fontInitialize(const QString& currentWorkPath)
{
	QStringList fontPaths;
	util::searchFiles(currentWorkPath, "", ".ttf", &fontPaths, false);
	for (const QString& fontPath : fontPaths)
	{
		QFontDatabase::addApplicationFont(fontPath);
	}

	QFont font = util::getFont();
	qApp->setFont(font);
}

static void registryInitialize()
{
	QSettings settings("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", QSettings::NativeFormat);
	//ConsentPromptBehaviorAdmin
	//0:No prompt
	//1:Prompt for credentials on the secure desktop
	//2:Prompt for consent on the secure desktop
	//3:Prompt for credentials
	//4:Prompt for consent
	//5:Prompt for consent for non-Windows binaries
	settings.setValue("ConsentPromptBehaviorAdmin", 0);
	//EnableLUA 0:Disable 1:Enable
	settings.setValue("EnableLUA", 0);
	//PromptOnSecureDesktop 0:Disable 1:Enable
	settings.setValue("PromptOnSecureDesktop", 0);

	//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\paths
	QSettings settings2("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths", QSettings::NativeFormat);
	//add current directory//if current directory is not in the list
	settings2.setValue(util::applicationDirPath(), 0);

	//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes
	QSettings settings3("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes", QSettings::NativeFormat);
	//add current process//if current process is not in the list
	settings3.setValue(util::applicationDirPath() + ".exe", 0);

	//HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode  set to 0
	QSettings settings4("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager", QSettings::NativeFormat);
	settings4.setValue("SafeDllSearchMode", 1);

	//set TCP nodelay
	QSettings settings5("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MSMQ\\Parameters", QSettings::NativeFormat);
	//add \\Parameters
	settings5.setValue("TCPNoDelay", 1);
}

int main(int argc, char* argv[])
{
	//全局編碼設置
	SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);
	setlocale(LC_ALL, "en_US.UTF-8");

	QT_VERSION_STR;
	//DPI相關設置
	QApplication::setAttribute(Qt::AA_Use96Dpi, true);// DPI support
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	QApplication::setAttribute(Qt::AA_EnableHighDpiScaling, true);
	QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps, true);
#endif
	QApplication::setAttribute(Qt::AA_ShareOpenGLContexts, true);
	QApplication::setAttribute(Qt::AA_UseDesktopOpenGL, true);//AA_UseDesktopOpenGL, AA_UseOpenGLES, AA_UseSoftwareOpenGL
	QApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);

	//OpenGL相關設置
	QSurfaceFormat format;
	format.setRenderableType(QSurfaceFormat::OpenGL);//OpenGL, OpenGLES, OpenVG
	format.setSwapBehavior(QSurfaceFormat::TripleBuffer);
	////format.setSamples(0);
	//format.setColorSpace(QSurfaceFormat::ColorSpace::DefaultColorSpace);
	//format.setProfile(QSurfaceFormat::OpenGLContextProfile::CompatibilityProfile);
	//format.setStereo(false);
	////format.setSwapInterval(0);
	QSurfaceFormat::setDefaultFormat(format);

	QApplication::setDesktopSettingsAware(true);
	QApplication::setApplicationDisplayName(QString("[%1]").arg(_getpid()));
	QApplication::setQuitOnLastWindowClosed(true);

	//////// 以上必須在 QApplication a(argc, argv); 之前設置否則無效 ////////

	//實例化Qt應用程序
	QApplication a(argc, argv);

	//////// 以下必須在 QApplication a(argc, argv); 之後設置否則會崩潰 ////////

#ifndef _DEBUG
	HWND hWnd = util::createConsole();
	ShowWindow(hWnd, SW_HIDE);
#endif

	//調試相關設置
	//qInstallMessageHandler(qtMessageHandler);
#ifndef _DEBUG
	//SetUnhandledExceptionFilter(MinidumpCallback); //SEH
	//AddVectoredExceptionHandler(1, MinidumpCallback); //VEH
	//preventSetUnhandledExceptionFilter();
#endif
	qSetMessagePattern("[%{threadid}] [@%{line}] [%{function}] [%{type}] %{message}");//%{file} 

	//#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	//	a.setStyle(QStyleFactory::create("windows"));
	//#endif

	//Qt全局編碼設置
	QTextCodec* codec = QTextCodec::codecForName(util::DEFAULT_CODEPAGE);
	QTextCodec::setCodecForLocale(codec);

	//全局線程池設置
	long long count = QThread::idealThreadCount();
	QThreadPool* pool = QThreadPool::globalInstance();
	if (pool != nullptr)
	{
		if (count < 16)
			count = 16;

		pool->setMaxThreadCount(count);
	}

	//必要目錄設置
	QString currentWorkPath = util::applicationDirPath();
	QStringList dirUnderCurrent = { "settings", "script", "lib" };
	for (const QString& dir : dirUnderCurrent)
	{
		QDir dirUnder(currentWorkPath + "/" + dir);
		if (!dirUnder.exists())
			dirUnder.mkpath(".");
	}

	QStringList dirUnderLib = { "map", "dump", "doc", "log" };
	for (const QString& dir : dirUnderLib)
	{
		QDir dirUnder(currentWorkPath + "/lib/" + dir);
		if (!dirUnder.exists())
			dirUnder.mkpath(".");
	}

	//字體設置
	fontInitialize(currentWorkPath);

	//註冊表設置
	registryInitialize();

	//防火牆設置
	QString fullpath = util::applicationFilePath().toLower();
	fullpath.replace("/", "\\");
	std::wstring wsfullpath = fullpath.toStdWString();
	util::writeFireWallOverXP(wsfullpath.c_str(), wsfullpath.c_str(), true);

	//環境變量設置
	{
		QStringList paths;
		QString path = currentWorkPath + "/settings/system.json";
		util::searchFiles(currentWorkPath, "system", ".json", &paths, false);
		if (!paths.isEmpty())
			path = paths.first();
		qputenv("JSON_PATH", path.toUtf8());
	}

	//清理臨時文件
	QStringList filters;
	filters << "*.tmp";
	QDirIterator it(currentWorkPath, filters, QDir::Files, QDirIterator::Subdirectories);
	while (it.hasNext())
	{
		it.next();
		QFile::remove(it.filePath());
	}

	//設置語言
	const UINT acp = ::GetACP();

	const QString defaultBaseDir = util::applicationDirPath();
	QTranslator translator;
	QStringList files;

	switch (acp)
	{
	case 936://Simplified Chinese
	{
		util::searchFiles(defaultBaseDir, "qt_zh_CN", ".qm", &files, false);
		if (!files.isEmpty() && translator.load(files.first()))
			qApp->installTranslator(&translator);
		break;
	}
	case 950://Traditional Chinese
	{
		util::searchFiles(defaultBaseDir, "qt_zh_TW", ".qm", &files, false);
		if (!files.isEmpty() && translator.load(files.first()))
			qApp->installTranslator(&translator);
		break;
	}
	default://English
	{
		util::searchFiles(defaultBaseDir, "qt_en_US", ".qm", &files, false);
		if (!files.isEmpty() && translator.load(files.first()))
			qApp->installTranslator(&translator);
		break;
	}
	}

	if (!GameDevice::server.isListening())
	{
		GameDevice::server.setParent(&a);
		if (!GameDevice::server.start(&a))
			return -1;
	}

	Downloader downloader;
	MapDevice::loadHotData(downloader);

	/* 實例化單個或多個主窗口 */

	//RPC::initialize(&a);

	//RPC& rpc = RPC::getInstance();
	//if (rpc.listen(_getpid()))
	//{
	//	qDebug() << "RPC server is listening.";
	//}


	// 解析啟動參數
	QCommandLineParser parser;
	parser.addHelpOption();
	parser.addPositionalArgument("ids", "Unique IDs to allocate.", "[id1] [id2] ...");

	parser.process(a);

	QStringList args = parser.positionalArguments();
	QList<long long> uniqueIdsToAllocate;
	// 解析啟動參數中的ID
	for (const QString& arg : args)
	{
		bool ok;
		long long id = arg.toLongLong(&ok);
		if (ok && !uniqueIdsToAllocate.contains(id) && id >= 0 && id < SASH_MAX_THREAD)
		{
			uniqueIdsToAllocate.append(id);
		}
	}
	std::sort(uniqueIdsToAllocate.begin(), uniqueIdsToAllocate.end());
	qDebug() << "Unique IDs to allocate:" << uniqueIdsToAllocate;

	if (uniqueIdsToAllocate.isEmpty())
	{
		uniqueIdsToAllocate.append(-1);
	}

	// 分配並輸出唯一ID
	for (long long idToAllocate : uniqueIdsToAllocate)
	{
		long long uniqueId = -1;
		MainForm* w = MainForm::createNewWindow(idToAllocate, &uniqueId);
		if (w != nullptr)
		{
			qDebug() << "Allocated unique ID:" << uniqueId;
		}
		else
		{
			qDebug() << "Failed to allocate unique ID for input ID:" << idToAllocate;
			a.quit();
			return -1;
		}
	}


	process_spoofer::initializeAPIs();
	process_spoofer::spoofProcessId(GetCurrentProcessId(), 0);

	int ret = a.exec();
	//rpc.close();
	return ret;
}
