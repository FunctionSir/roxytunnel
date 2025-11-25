/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-10-03 17:05:50
 * @LastEditTime: 2025-10-09 21:16:32
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/core/shared/log.go
 */

package shared

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

type LogLevel uint8

// We use iota to make it act like a enum in C/CPP.
//
// That means LogLevelDebug = 0, LogLevelInfo = 1, LogLevelWarn = 2 ...
//
// About Fatal:
//
// Fatal will ALWAYS trigger a panic! Be careful!
//
// Do NOT use it unless TERMINATE is intended!
const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
)

const (
	LogLevelDebugStr   string = "DEBUG"
	LogLevelInfoStr    string = "INFO"
	LogLevelWarnStr    string = "WARN"
	LogLevelErrorStr   string = "ERROR"
	LogLevelFatalStr   string = "FATAL" // Fatal will ALWAYS trigger a panic! Be careful!
	LogLevelUnknownStr string = "UNKNOWN"
)

var (
	LogLevelStr = [...]string{LogLevelDebugStr, LogLevelInfoStr, LogLevelWarnStr, LogLevelErrorStr, LogLevelFatalStr}
)

var (
	MinimumLogLevel LogLevel = LogLevelWarn
)

var (
	// This TIMESTAMP is a TIMESTAMP as ms! NOT second!
	QueryLogToDB string = "INSERT INTO `LOG` (`TIMESTAMP`, `LEVEL`, `MESSAGE`) VALUES (?,?,?);"
)

func (level LogLevel) String() string {
	if level >= LogLevelFatal+1 || int(level) >= len(LogLevelStr) {
		return LogLevelUnknownStr
	}
	return LogLevelStr[level]
}

func (level LogLevel) ShouldLog() bool {
	return level >= MinimumLogLevel
}

func LogToAll(ctx context.Context, db *sql.DB, level LogLevel, msg string) {
	if !level.ShouldLog() {
		return
	}

	// Log to screen.
	log.Printf("[%s] %s\n", level, strings.TrimSpace(msg))

	// Log to DB.
	if db == nil {
		LogToScreen(LogLevelError, fmt.Sprintf("Can not log this to DB: Level: %s; Message: %s", level, msg))
		return
	}
	_, err := db.ExecContext(ctx, QueryLogToDB, time.Now().UnixMilli(), level.String(), msg)
	if err != nil {
		LogToScreen(LogLevelError, fmt.Sprintf("Error occurred during writing log to DB: %s.", err.Error()))
		LogToScreen(LogLevelError, fmt.Sprintf("Can not log this to DB: Level: %s; Message: %s", level, msg))
	}

	if level >= LogLevelFatal {
		panic(msg)
	}
}

func LogToScreen(level LogLevel, msg string) {
	if !level.ShouldLog() {
		return
	}
	log.Printf("[%s] %s\n", level, strings.TrimSpace(msg))
	if level >= LogLevelFatal {
		panic(msg)
	}
}

func LogToDatabase(ctx context.Context, db *sql.DB, level LogLevel, msg string) {
	if !level.ShouldLog() {
		return
	}
	if db == nil {
		LogToScreen(LogLevelError, fmt.Sprintf("Can not log this to DB: Level: %s; Message: %s", level, msg))
		return
	}
	_, err := db.ExecContext(ctx, QueryLogToDB, time.Now().UnixMilli(), level.String(), msg)
	if err != nil {
		LogToScreen(LogLevelError, fmt.Sprintf("Error occurred during writing log to DB: %s.", err.Error()))
		LogToScreen(LogLevelError, fmt.Sprintf("Can not log this to DB: Level: %s; Message: %s", level, msg))
	}
	if level >= LogLevelFatal {
		panic(msg)
	}
}

func Check(ctx context.Context, db *sql.DB, err error, where string) {
	if err != nil {
		msg := fmt.Sprintf("Got a fatal error: %s from %s.", err.Error(), where)
		LogToAll(ctx, db, LogLevelFatal, msg)
	}
}

func Ensure(ctx context.Context, db *sql.DB, condition bool, msg string) {
	if !condition {
		LogToAll(ctx, db, LogLevelFatal, msg)
	}
}
