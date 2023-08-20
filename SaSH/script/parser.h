﻿/*
				GNU GENERAL PUBLIC LICENSE
				   Version 2, June 1991
COPYRIGHT (C) Bestkakkoii 2023 All Rights Reserved.
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

#pragma once
#include "lexer.h"
#include <QStack>
#include <functional>

#include "threadplugin.h"
#include "util.h"

using CommandRegistry = std::function<qint64(qint64 currentLine, const TokenMap& token)>;

//callbak
using ParserCallBack = std::function<qint64(qint64 currentLine, const TokenMap& token)>;

using VariantSafeHash = util::SafeHash<QString, QVariant>;

enum CompareArea
{
	kAreaPlayer,
	kAreaPet,
	kAreaItem,
	kAreaCount,
};

enum CompareType
{
	kCompareTypeNone,
	kPlayerName,
	kPlayerFreeName,
	kPlayerLevel,
	kPlayerHp,
	kPlayerMaxHp,
	kPlayerHpPercent,
	kPlayerMp,
	kPlayerMaxMp,
	kPlayerMpPercent,
	kPlayerExp,
	kPlayerMaxExp,
	kPlayerStone,
	kPlayerVit,
	kPlayerStr,
	kPlayerTgh,
	kPlayerDex,
	kPlayerAtk,
	kPlayerDef,
	kPlayerAgi,
	kPlayerChasma,
	kPlayerTurn,
	kPlayerEarth,
	kPlayerWater,
	kPlayerFire,
	kPlayerWind,

	kPetName,
	kPetFreeName,
	kPetLevel,
	kPetHp,
	kPetMaxHp,
	kPetHpPercent,
	kPetExp,
	kPetMaxExp,
	kPetAtk,
	kPetDef,
	kPetAgi,
	kPetLoyal,
	kPetTurn,
	kPetState,
	kPetEarth,
	kPetWater,
	kPetFire,
	kPetWind,

	kitemCount,
	kItemName,
	kItemMemo,
	kItemDura,
	kItemLevel,
	kItemStack,

	kTeamName,
	kTeamLevel,
	kTeamHp,
	kTeamMaxHp,
	kTeamHpPercent,
	kTeamMp,

	kCardName,
	kCardOnlineState,
	kCardTurn,
	kCardDp,
	kCardLevel,

	kTeamCount,
	kPetCount,

	kMapName,
	kMapFloor,
	kMapX,
	kMapY,

};

inline static const QHash<QString, CompareType> compareCardTypeMap = {
	{ u8"name", kCardName },
	{ u8"online", kCardOnlineState },
	{ u8"turn", kCardTurn },
	{ u8"dp", kCardDp },
	{ u8"lv", kCardLevel },
};

inline static const QHash<QString, CompareType> compareItemTypeMap = {
	{ u8"count", kitemCount },
	{ u8"name", kItemName },
	{ u8"memo", kItemMemo },
	{ u8"dura", kItemDura },
	{ u8"lv", kItemLevel },
	{ u8"stack", kItemStack },
};

inline static const QHash<QString, CompareType> compareTeamTypeMap = {
	{ u8"name", kTeamName },
	{ u8"lv", kTeamLevel },
	{ u8"hp", kTeamHp },
	{ u8"maxhp", kTeamMaxHp },
	{ u8"hpp", kTeamHpPercent },
	{ u8"mp", kTeamMp },
};

inline static const QHash<QString, CompareType> compareMapTypeMap = {
	{ u8"name", kMapName },
	{ u8"floor", kMapFloor },
	{ u8"x", kMapX },
	{ u8"y", kMapY },
};

inline static const QHash<QString, CompareType> comparePcTypeMap = {
	{ u8"name", kPlayerName },
	{ u8"fname", kPlayerFreeName },
	{ u8"lv", kPlayerLevel },
	{ u8"hp", kPlayerHp },
	{ u8"maxhp", kPlayerMaxHp },
	{ u8"hpp", kPlayerHpPercent },
	{ u8"mp", kPlayerMp },
	{ u8"maxmp", kPlayerMaxMp },
	{ u8"mpp", kPlayerMpPercent },
	{ u8"exp", kPlayerExp },
	{ u8"maxexp", kPlayerMaxExp },
	{ u8"stone", kPlayerStone },
	{ u8"vit", kPlayerVit },
	{ u8"str", kPlayerStr },
	{ u8"tgh", kPlayerTgh },
	{ u8"def", kPlayerDex },
	{ u8"atk", kPlayerAtk },
	{ u8"def", kPlayerDef },
	{ u8"agi", kPlayerAgi },
	{ u8"chasma", kPlayerChasma },
	{ u8"turn", kPlayerTurn },
	{ u8"earth", kPlayerEarth },
	{ u8"water", kPlayerWater },
	{ u8"fire", kPlayerFire },
	{ u8"wind", kPlayerWind },
};

inline static const QHash<QString, CompareType> comparePetTypeMap = {
	{ u8"name", kPetName },
	{ u8"fname", kPetFreeName },
	{ u8"lv", kPetLevel },
	{ u8"hp", kPetHp },
	{ u8"maxhp", kPetMaxHp },
	{ u8"hpp", kPetHpPercent },
	{ u8"exp", kPetExp },
	{ u8"maxexp", kPetMaxExp },
	{ u8"atk", kPetAtk },
	{ u8"def", kPetDef },
	{ u8"agi", kPetAgi },
	{ u8"loyal", kPetLoyal },
	{ u8"turn", kPetTurn },
	{ u8"state", kPetState },
	{ u8"earth", kPetEarth },
	{ u8"water", kPetWater },
	{ u8"fire", kPetFire },
	{ u8"wind", kPetWind },
};

inline static const QHash<QString, CompareType> compareAmountTypeMap = {
	{ u8"道具數量", kitemCount },
	{ u8"組隊人數", kTeamCount },
	{ u8"寵物數量", kPetCount },

	{ u8"道具数量", kitemCount },
	{ u8"组队人数", kTeamCount },
	{ u8"宠物数量", kPetCount },

	{ u8"ifitem", kitemCount },
	{ u8"ifteam", kTeamCount },
	{ u8"ifpet", kPetCount },
};

static const QSet<RESERVE> operatorTypes = {
	TK_ADD, //"+"
	TK_SUB, // '-'
	TK_MUL, // '*'
	TK_DIV, // '/'
	TK_MOD, // '%'
	TK_SHL, // "<<"
	TK_SHR, // ">>"
	TK_AND, // "&"
	TK_OR, // "|"
	TK_NOT, // "~"
	TK_XOR, // "^"
	TK_NEG, //"!" (與C++的 ! 同義)
	TK_INC, // "++" (與C++的 ++ 同義)
	TK_DEC, // "--" (與C++的 -- 同義)
};

static const QSet<RESERVE> relationalOperatorTypes = {
	TK_EQ, // "=="
	TK_NEQ, // "!="
	TK_GT, // ">"
	TK_LT, // "<"
	TK_GEQ, // ">="
	TK_LEQ, // "<="
};

enum JumpBehavior
{
	SuccessJump,
	FailedJump,
};

class Parser : public ThreadPlugin
{
	Q_OBJECT
public:
	enum
	{
		kStop = 0,
		kContinue = 1,
		kPause,
		kResume,
	};

	enum ParserError
	{
		kNoError = 0,
		kException,
		kUndefinedVariable,
	};

	enum ParserCommandStatus
	{
		kHasJump = 0,
		kNoChange,
		kError,
		kLabelError,
		kUnknownCommand,
		kArgError = 100,
	};

	enum Mode
	{
		kSync,
		kAsync,
	};

	enum StackMode
	{
		kModeCallStack,
		kModeJumpStack,
	};

public:
	inline ParserError lastCriticalError() const { return lastCriticalError_; }

	void setLastErrorMessage(const QString& msg) { lastErrorMesssage_ = msg; }
	QString getLastErrorMessage() const { return lastErrorMesssage_; }

	//設置所有標籤所在行號數據
	inline void setLabels(const QHash<QString, qint64>& labels) { labels_ = labels; }

	//設置腳本所有Token數據
	inline void setTokens(const QHash<qint64, TokenMap>& tokens) { tokens_ = tokens; }

	Q_REQUIRED_RESULT inline bool hasToken() const { return !tokens_.isEmpty(); }

	Q_REQUIRED_RESULT inline const QHash<qint64, TokenMap> getToken() const { return tokens_; }

	inline void setCallBack(const ParserCallBack& callBack) { callBack_ = callBack; }

	inline void setCurrentLine(qint64 line) { lineNumber_ = line; }

	inline void setMode(Mode mode) { mode_ = mode; }

	inline void insertUserCallBack(const QString& name, const QString& type)
	{
		//確保一種類型只能被註冊一次
		for (auto it = userRegCallBack_.cbegin(); it != userRegCallBack_.cend(); ++it)
		{
			if (it.value() == type)
				return;
			if (it.key() == name)
				return;
		}

		userRegCallBack_.insert(name, type);
	}

	inline bool getErrorCallBackLabelName(QString* pname) const
	{
		if (pname == nullptr)
			return false;

		for (auto it = userRegCallBack_.cbegin(); it != userRegCallBack_.cend(); ++it)
		{
			if (it.value() == "err")
			{
				*pname = it.key();
				return true;
			}
		}
		return false;
	}

	inline bool getDtorCallBackLabelName(QString* pname)
	{
		if (pname == nullptr)
			return false;

		if (dtorCallBackFlag_ != 0)
			return false;

		QHash<QString, qint64> hash = getLabels();
		constexpr const char* DTOR = "dtor";
		if (hash.contains(DTOR))
		{
			dtorCallBackFlag_ = 1;
			*pname = DTOR;
			return true;
		}

		return false;
	}

	inline void registerFunction(const QString& commandName, const CommandRegistry& function)
	{
		commandRegistry_.insert(commandName, static_cast<CommandRegistry>(function));
	}

	template <typename T>
	Q_REQUIRED_RESULT inline T getVar(const QString& name)
	{
		QString newName = name;
		if (variables_->contains(newName))
		{
			return variables_->value(newName).value<T>();
		}
		else
		{
			return QVariant::fromValue(name).value<T>();
		}
	}

	bool jump(qint64 line, bool noStack);
	void jumpto(qint64 line, bool noStack);
	bool jump(const QString& name, bool noStack);

	bool checkString(const TokenMap& TK, qint64 idx, QString* ret);
	bool checkInteger(const TokenMap& TK, qint64 idx, qint64* ret);

	bool toVariant(const TokenMap& TK, qint64 idx, QVariant* ret);
	bool compare(const QVariant& a, const QVariant& b, RESERVE type) const;

	QVariant checkValue(const TokenMap TK, qint64 idx, QVariant::Type);
	qint64 checkJump(const TokenMap& TK, qint64 idx, bool expr, JumpBehavior behavior);

	bool isSubScript() const { return isSubScript_; }
	void setSubScript(bool isSubScript) { isSubScript_ = isSubScript; }

public:
	Parser();
	virtual ~Parser();

	//解析腳本
	void parse(qint64 line = 0);

	Q_REQUIRED_RESULT inline VariantSafeHash* getGlobalVarPointer() const
	{
		if (globalVarLock_ == nullptr)
			return nullptr;

		QReadLocker locker(globalVarLock_);
		return variables_;
	}

	Q_REQUIRED_RESULT inline QReadWriteLock* getGlobalVarLockPointer() const { return globalVarLock_; }

	Q_REQUIRED_RESULT inline bool isGlobalVarContains(const QString& name) const
	{
		if (globalVarLock_ == nullptr)
			return false;

		QReadLocker locker(globalVarLock_);
		if (variables_ != nullptr)
			return variables_->contains(name);
		return false;
	}

	inline QVariant getGlobalVarValue(const QString& name) const
	{
		if (globalVarLock_ == nullptr)
			return QVariant();

		QReadLocker locker(globalVarLock_);
		if (variables_ != nullptr)
			return variables_->value(name, 0);
		return QVariant();
	}

	void insertGlobalVar(const QString& name, const QVariant& value);

	inline void insertVar(const QString& name, const QVariant& value)
	{
		QHash<QString, QVariant> args = getLocalVars();
		if (args.contains(name))
			insertLocalVar(name, value);
		else
			insertGlobalVar(name, value);
	}

	inline void setVariablesPointer(VariantSafeHash* pvariables, QReadWriteLock* plock)
	{
		if (!isSubScript())
			return;

		variables_ = pvariables;
		globalVarLock_ = plock;
	}

	QHash<QString, qint64> getLabels() { return labels_; }

	Q_REQUIRED_RESULT inline QVariantHash getLocalVars()
	{
		if (!localVarStack_.isEmpty())
			return localVarStack_.top();
		else
		{
			localVarStack_.push(QVariantHash{});
			return localVarStack_.top();
		}
	}

private:
	void processTokens();
	qint64 processCommand();
	void processVariable(RESERVE type);
	void processLocalVariable();
	void processVariableIncDec();
	void processVariableCAOs();
	void processVariableExpr();
	void processMultiVariable();
	void processFormation();
	void processRandom();
	bool processCall();
	bool processGoto();
	bool processJump();
	void processReturn();
	void processBack();
	void processLabel();
	void processClean();
	void processDelay();
	bool processFor();
	bool processEndFor();
	bool processBreak();
	bool processContinue();
	bool processGetSystemVarValue(const QString& varName, QString& valueStr, QVariant& varValue);
	bool processIfCompare();

	bool isTextWrapped(const QString& text, const QString& keyword);
	void replaceToVariable(QString& str);
	void replaceSysConstKeyword(QString& expr);
	void cycleReplace(QString& expr);
	bool checkCallStack();
	bool checkFuzzyValue(const QString& varName, QVariant* pvalue);

	template<typename T>
	T calc(const QVariant& a, const QVariant& b, RESERVE operatorType);

	template <typename T>
	bool exprMakeValue(const QString& expr, T* ret);

	template <typename T>
	bool exprTo(QString expr, T* ret);

	template <typename T>
	bool exprTo(T value, QString expr, T* ret);

	void handleError(qint64 err, const QString& addition = "");
	void checkArgs();
	void recordFunctionChunks();
	void recordForChunks();

	inline Q_REQUIRED_RESULT bool isLocalVarContains(const QString& name)
	{
		QVariantHash hash = getLocalVars();
		if (hash.contains(name))
			return true;

		return false;
	}

	inline Q_REQUIRED_RESULT QVariant getLocalVarValue(const QString& name)
	{
		QVariantHash hash = getLocalVars();
		if (hash.contains(name))
			return hash.value(name);

		return QVariant();
	}

	inline void removeLocalVar(const QString& name)
	{
		QVariantHash& hash = getLocalVarsRef();
		if (hash.contains(name))
			hash.remove(name);
	}

	void insertLocalVar(const QString& name, const QVariant& value);

	inline void removeGlobalVar(const QString& name)
	{
		if (globalVarLock_ == nullptr)
			return;

		QWriteLocker locker(globalVarLock_);
		if (variables_ != nullptr)
			variables_->remove(name);
	}

	inline void clearGlobalVar()
	{
		if (globalVarLock_ == nullptr)
			return;

		QWriteLocker locker(globalVarLock_);
		if (variables_ != nullptr)
			variables_->clear();
	}

	Q_REQUIRED_RESULT inline QVariantHash& getLocalVarsRef()
	{
		if (!localVarStack_.isEmpty())
			return localVarStack_.top();
		else
		{
			localVarStack_.push(QVariantHash{});
			return localVarStack_.top();
		}
	}

	inline void next() { ++lineNumber_; }

	Q_REQUIRED_RESULT inline bool empty() const { return !tokens_.contains(lineNumber_); }
	Q_REQUIRED_RESULT inline RESERVE getCurrentFirstTokenType() const
	{
		Token token = currentLineTokens_.value(0, Token{});
		return token.type;
	}

	template <typename T>
	Q_REQUIRED_RESULT inline T getToken(qint64 index) const
	{
		if (currentLineTokens_.contains(index))
		{
			QVariant data = currentLineTokens_.value(index).data;
			if (data.isValid())
				return currentLineTokens_.value(index).data.value<T>();
		}
		//如果是整數返回 -1
		if (std::is_same<T, qint64>::value)
			return 0;
		return T();
	}

	Q_REQUIRED_RESULT inline RESERVE getTokenType(qint64 index) const { return currentLineTokens_.value(index).type; }
	Q_REQUIRED_RESULT TokenMap getCurrentTokens() const { return currentLineTokens_; }
	void variableCalculate(RESERVE op, QVariant* var, const QVariant& varValue);
	qint64 matchLineFromLabel(const QString& label) const
	{
		if (functionChunks_.contains(label))
			return -1;
		return labels_.value(label, -1);
	}
	qint64 matchLineFromFunction(const QString& funcName) const
	{
		if (functionChunks_.contains(funcName))
			return functionChunks_.value(funcName).begin;
		else
			return -1;
	}

	Q_REQUIRED_RESULT inline QVariantList& getArgsRef()
	{
		if (!callArgsStack_.isEmpty())
			return callArgsStack_.top();
		else
			return emptyArgs_;
	}

	void generateStackInfo(qint64 type);

private:
	//函數代碼塊
	typedef struct tagFunctionChunk
	{
		QString name;
		qint64 begin = -1;
		qint64 end = -1;
	} FunctionChunk;

	typedef struct tagForChunk
	{
		QString name;
		qint64 begin = -1;
		qint64 end = -1;
	} ForChunk;

	QHash<qint64, TokenMap> tokens_;						//當前運行腳本的每一行token
	mutable QReadWriteLock* globalVarLock_ = nullptr;		//全局變量鎖指針
	VariantSafeHash* variables_ = nullptr;					//全局變量容器指針
	QHash<QString, qint64> labels_;							//所有標記/函數所在行記錄
	QHash<QString, FunctionChunk> functionChunks_;          //函數代碼塊紀錄，用於避免直接執行到function，確保只有 call 才能執行到 function
	QHash<QString, ForChunk> forChunks_;
	QHash<QString, QString> userRegCallBack_;				//用戶註冊的回調函數
	QHash<QString, CommandRegistry> commandRegistry_;		//所有已註冊的腳本命令函數指針

	QStack<qint64> callStack_;								//"調用"命令所在行棧
	QStack<qint64> jmpStack_;								//"跳轉"命令所在行棧
	QStack<QPair<QString, qint64>> forStack_;				//"遍歷"命令所在行棧
	QStack<QVariantList> callArgsStack_;					//"調用"命令參數棧
	QVariantList emptyArgs_;								//空參數(參數棧為空得情況下壓入一個空容器)
	QStack<QVariantHash> localVarStack_;					//局變量棧
	QVariantHash emptyLocalVars_;							//空局變量(局變量棧為空得情況下壓入一個空容器)

	TokenMap currentLineTokens_;							//當前行token
	RESERVE currentType_ = TK_UNK;							//當前行第一個token類型
	qint64 lineNumber_ = 0;									//當前行號

	ParserError lastCriticalError_ = kNoError;				//最後一次錯誤

	QString lastErrorMesssage_;								//最後一次錯誤信息

	ParserCallBack callBack_ = nullptr;						//腳本回調函數

	Mode mode_ = kSync;										//解析模式(同步|異步)

	qint64 dtorCallBackFlag_ = 0;							//析構回調函數標記
	qint64 ctorCallBackFlag_ = 0;							//建構回調函數標記
	bool skipFunctionChunkDisable_ = false;					//是否跳過函數代碼塊檢查

	bool isSubScript_ = false;								//是否是子腳本		
};